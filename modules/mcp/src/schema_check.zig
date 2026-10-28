// SPDX-License-Identifier: MIT
//! A JSON Schema 2020-12 SUBSET instance validator over `std.json.Value`.
//!
//! Why it exists: the official MCP SDKs check a `tools/call` `arguments` object
//! against the tool's `inputSchema` before the handler runs (a mismatch becomes
//! a tool result with `isError:true` and the message), and `structuredContent`
//! against `outputSchema`. This file is the checker; the server decides what to
//! do when `compile` says the schema is outside the subset (the intended answer
//! is "do not validate that tool", not "refuse the tool").
//!
//! The subset, by keyword:
//!
//!   - boolean schemas; `type` (string or array; `integer` is a number with a
//!     zero fractional part, so `1.0` is an integer); `enum`; `const`;
//!   - objects: `properties`, `required`, `additionalProperties` (bool or
//!     schema), `minProperties`, `maxProperties`;
//!   - arrays: `prefixItems`, `items` (2020-12 meaning: the items AFTER the
//!     prefix), `minItems`, `maxItems`, `uniqueItems`;
//!   - strings: `minLength`, `maxLength` (Unicode code points, not bytes);
//!   - numbers: `minimum`, `maximum`, `exclusiveMinimum`, `exclusiveMaximum`,
//!     `multipleOf`;
//!   - `allOf`, `anyOf`, `oneOf`, `not`, `if`/`then`/`else`;
//!   - `$ref` ONLY to `#`, `#/$defs/<name>` and `#/definitions/<name>` (`~0`,
//!     `~1` and `%XX` unescaped), nested at most `max_ref_depth` deep;
//!   - `$defs` / `definitions` (compiled, so a bad schema in them is reported).
//!
//! ACCEPTED AND IGNORED because they never change validity: `title`,
//! `description`, `default`, `examples`, `$schema`, `$comment`, `deprecated`,
//! `readOnly`, `writeOnly`, `format` (annotation only in 2020-12), `contentEncoding`,
//! `contentMediaType`, any `x-*` key (`x-mcp-header` included), and `$id` at the
//! root. `pattern` is also accepted and IGNORED: there is no regex engine here
//! (the `regex` module could be wired in later), so `pattern` is "not checked"
//! and a value that violates it validates. Every other keyword
//! (`patternProperties`, `contains`, `dependentRequired`, `$anchor`,
//! `$dynamicRef`, a nested `$id`, ...) makes `compile` fail with
//! `UnsupportedKeyword`: a schema we cannot fully check is reported, not
//! half-checked.
//!
//! Deviations from 2020-12, all deliberate:
//!
//!   - `$ref` resolves only inside the root document and only to the three forms
//!     above; the depth cap means a legitimately recursive schema over an instance
//!     nested deeper than `max_ref_depth` references fails with keyword `$ref`;
//!   - numbers are compared as `i64` when both sides are, otherwise as `f64`; a
//!     literal outside the `i64` range is an `f64` (`1e400` is infinite and
//!     compares greater than everything);
//!   - `multipleOf` on two integers is exact; otherwise `x / d` must be finite
//!     and within a relative 1e-9 of a whole number (so `0.07` is a multiple of
//!     `0.01`, which ajv and Python jsonschema refuse by default);
//!   - `uniqueItems` charges one step per comparison, so it shares the budget;
//!   - `then` / `else` without `if` are compiled and ignored (as in the spec);
//!   - instance nesting deeper than `max_depth` is a `depth` failure, never a
//!     stack overflow.
//!
//! Nothing here panics on any schema or instance: every path returns an error
//! or a `Failure`. A `Schema` borrows the `std.json.Value` it was compiled from.

const std = @import("std");

/// The longest chain of `$ref` resolutions one validation may follow. A schema
/// such as `{"$ref":"#"}` loops through it and fails instead of recursing.
pub const max_ref_depth = 64;

/// The deepest nesting of schema (and instance) levels `compile` and `validate`
/// walk; it only bounds the recursion.
pub const max_depth = 256;

/// How many schema applications (`apply` calls) one `validate` may spend. A
/// benign recursive schema with `anyOf`/`oneOf` re-validates subtrees per
/// branch, so an attacker-chosen instance can make the work exponential; the
/// budget turns that into a `"budget"` failure.
pub const max_steps: u32 = 1_000_000;

pub const CompileError = error{
    OutOfMemory,
    /// The schema is neither a JSON object nor a boolean.
    SchemaNotObject,
    /// A keyword outside the subset (see the file header).
    UnsupportedKeyword,
    /// A supported keyword with a value of the wrong shape (`"required": 3`),
    /// or a schema nested deeper than `max_depth`.
    BadKeywordValue,
    /// A `$ref` that is not `#`, `#/$defs/<name>` or `#/definitions/<name>`, or
    /// whose target does not exist.
    BadRef,
};

/// One reason an instance is invalid. Slices live in the `arena` given to
/// `validate`.
pub const Failure = struct {
    /// RFC 6901 JSON Pointer to the offending instance location; `""` = root.
    pointer: []const u8,
    /// The schema keyword that failed (`"type"`, `"required"`, ...).
    keyword: []const u8,
    /// Human-readable, fit for a tool-result message.
    message: []const u8,
};

pub const Schema = struct {
    root: std.json.Value,

    /// Checks that `schema` stays inside the subset and returns a validator that
    /// borrows it (`arena` is reserved for compiled state; the subset needs none
    /// yet, so the schema value itself must outlive the result).
    pub fn compile(arena: std.mem.Allocator, schema: std.json.Value) CompileError!Schema {
        _ = arena; // reserved: the subset compiles to nothing but the checked value
        if (schema != .object and schema != .bool) return error.SchemaNotObject;
        try checkSchema(schema, schema, 0);
        return .{ .root = schema };
    }

    /// Validates `instance`: null if valid, otherwise the FIRST failure in a
    /// fixed keyword order (independent of the key order in the schema).
    /// Allocates only the `Failure` strings, in `arena`.
    pub fn validate(self: *const Schema, arena: std.mem.Allocator, instance: std.json.Value) error{OutOfMemory}!?Failure {
        return self.validateBudget(arena, instance, max_steps);
    }

    /// `validate` with an explicit step budget. When it runs out the result is
    /// a failure with keyword `"budget"` (pointer: where it ran out), whatever
    /// the partial evaluation had concluded.
    pub fn validateBudget(self: *const Schema, arena: std.mem.Allocator, instance: std.json.Value, steps: u32) error{OutOfMemory}!?Failure {
        var budget: Budget = .{ .left = steps };
        const c: Checker = .{ .arena = arena, .root = self.root, .budget = &budget };
        const result = try c.apply(self.root, instance, null, 0, 0);
        if (budget.pointer) |ptr| return .{ .pointer = ptr, .keyword = "budget", .message = "schema check exceeded its step budget" };
        return result;
    }
};

// ── compile ──────────────────────────────────────────────────────────────

const Kw = enum {
    type,
    @"enum",
    @"const",
    properties,
    required,
    additionalProperties,
    minProperties,
    maxProperties,
    items,
    prefixItems,
    minItems,
    maxItems,
    uniqueItems,
    minLength,
    maxLength,
    minimum,
    maximum,
    exclusiveMinimum,
    exclusiveMaximum,
    multipleOf,
    allOf,
    anyOf,
    oneOf,
    not,
    @"if",
    then,
    @"else",
    @"$ref",
    @"$defs",
    definitions,
    pattern,
    @"$id",
};

/// Keywords that never change validity.
const annotations = [_][]const u8{
    "title",     "description", "default",         "examples",
    "$schema",   "$comment",    "deprecated",      "readOnly",
    "writeOnly", "format",      "contentEncoding", "contentMediaType",
};

fn isAnnotation(key: []const u8) bool {
    if (std.mem.startsWith(u8, key, "x-")) return true;
    for (annotations) |a| if (std.mem.eql(u8, a, key)) return true;
    return false;
}

fn isSchemaValue(v: std.json.Value) bool {
    return v == .object or v == .bool;
}

fn checkSchema(root: std.json.Value, schema: std.json.Value, depth: u32) CompileError!void {
    if (depth > max_depth) return error.BadKeywordValue;
    if (schema == .bool) return;
    if (schema != .object) return error.BadKeywordValue;
    var it = schema.object.iterator();
    while (it.next()) |e| {
        const key = e.key_ptr.*;
        const v = e.value_ptr.*;
        if (isAnnotation(key)) continue;
        const kw = std.meta.stringToEnum(Kw, key) orelse return error.UnsupportedKeyword;
        switch (kw) {
            .@"const" => {},
            .@"enum" => if (v != .array) return error.BadKeywordValue,
            .type => try checkType(v),
            .pattern, .@"$id" => {
                if (v != .string) return error.BadKeywordValue;
                if (kw == .@"$id" and depth != 0) return error.UnsupportedKeyword;
            },
            .properties, .@"$defs", .definitions => {
                if (v != .object) return error.BadKeywordValue;
                var pit = v.object.iterator();
                while (pit.next()) |p| {
                    if (!isSchemaValue(p.value_ptr.*)) return error.BadKeywordValue;
                    try checkSchema(root, p.value_ptr.*, depth + 1);
                }
            },
            .required => {
                if (v != .array) return error.BadKeywordValue;
                for (v.array.items) |r| if (r != .string) return error.BadKeywordValue;
            },
            .additionalProperties, .items, .not, .@"if", .then, .@"else" => {
                if (!isSchemaValue(v)) return error.BadKeywordValue;
                try checkSchema(root, v, depth + 1);
            },
            .prefixItems, .allOf, .anyOf, .oneOf => {
                if (v != .array or v.array.items.len == 0) return error.BadKeywordValue;
                for (v.array.items) |s| {
                    if (!isSchemaValue(s)) return error.BadKeywordValue;
                    try checkSchema(root, s, depth + 1);
                }
            },
            .minProperties, .maxProperties, .minItems, .maxItems, .minLength, .maxLength => {
                if (asCount(v) == null) return error.BadKeywordValue;
            },
            .uniqueItems => if (v != .bool) return error.BadKeywordValue,
            .minimum, .maximum, .exclusiveMinimum, .exclusiveMaximum => {
                if (toNum(v) == null) return error.BadKeywordValue;
            },
            .multipleOf => {
                const n = toNum(v) orelse return error.BadKeywordValue;
                if (!(numToF64(n) > 0)) return error.BadKeywordValue;
            },
            .@"$ref" => {
                if (v != .string) return error.BadKeywordValue;
                if (resolveRef(root, v.string) == null) return error.BadRef;
            },
        }
    }
}

const type_names = [_][]const u8{ "null", "boolean", "object", "array", "number", "string", "integer" };

fn isTypeName(s: []const u8) bool {
    for (type_names) |t| if (std.mem.eql(u8, t, s)) return true;
    return false;
}

fn checkType(v: std.json.Value) CompileError!void {
    switch (v) {
        .string => |s| if (!isTypeName(s)) return error.BadKeywordValue,
        .array => |a| {
            if (a.items.len == 0) return error.BadKeywordValue;
            for (a.items) |t| if (t != .string or !isTypeName(t.string)) return error.BadKeywordValue;
        },
        else => return error.BadKeywordValue,
    }
}

/// A non-negative whole number that fits a `u64` (`3` and `3.0` both count).
fn asCount(v: std.json.Value) ?u64 {
    const n = toNum(v) orelse return null;
    switch (n) {
        .int => |i| return if (i >= 0) @intCast(i) else null,
        .f => |f| {
            if (!std.math.isFinite(f) or f < 0 or f != @floor(f) or f >= 9007199254740992.0) return null;
            return @intFromFloat(f);
        },
    }
}

/// Resolves `ref` against `root`: `#`, `#/$defs/<name>` or `#/definitions/<name>`.
/// Null if it is another form, the name is missing, or the target is no schema.
fn resolveRef(root: std.json.Value, ref: []const u8) ?std.json.Value {
    if (std.mem.eql(u8, ref, "#")) return root;
    if (root != .object) return null;
    const prefixes = [_]struct { text: []const u8, key: []const u8 }{
        .{ .text = "#/$defs/", .key = "$defs" },
        .{ .text = "#/definitions/", .key = "definitions" },
    };
    for (prefixes) |p| {
        if (!std.mem.startsWith(u8, ref, p.text)) continue;
        var buf: [256]u8 = undefined;
        const name = unescapeName(&buf, ref[p.text.len..]) orelse return null;
        const defs = root.object.get(p.key) orelse return null;
        if (defs != .object) return null;
        const target = defs.object.get(name) orelse return null;
        return if (isSchemaValue(target)) target else null;
    }
    return null;
}

/// URI percent-decoding, then JSON Pointer `~1` / `~0`, of ONE pointer
/// segment. Null if it does not fit `buf`, has a bad `%XX`, or (after decoding)
/// contains `/` — that would be a deeper pointer, which is not supported.
fn unescapeName(buf: []u8, raw: []const u8) ?[]const u8 {
    var n: usize = 0;
    var i: usize = 0;
    while (i < raw.len) : (i += 1) {
        var c = raw[i];
        if (c == '%') {
            if (i + 2 >= raw.len) return null;
            const hi = std.fmt.charToDigit(raw[i + 1], 16) catch return null;
            const lo = std.fmt.charToDigit(raw[i + 2], 16) catch return null;
            c = hi * 16 + lo;
            i += 2;
        }
        if (c == '/') return null;
        if (n >= buf.len) return null;
        buf[n] = c;
        n += 1;
    }
    // `~0` / `~1`, in place (the result is never longer than the input).
    var out: usize = 0;
    var j: usize = 0;
    while (j < n) : (j += 1) {
        if (buf[j] == '~') {
            if (j + 1 >= n) return null;
            buf[out] = switch (buf[j + 1]) {
                '0' => '~',
                '1' => '/',
                else => return null,
            };
            j += 1;
        } else buf[out] = buf[j];
        out += 1;
    }
    return buf[0..out];
}

// ── numbers and equality ─────────────────────────────────────────────────

const Num = union(enum) { int: i64, f: f64 };

fn toNum(v: std.json.Value) ?Num {
    switch (v) {
        .integer => |i| return .{ .int = i },
        .float => |f| return .{ .f = f },
        .number_string => |s| {
            if (std.fmt.parseInt(i64, s, 10)) |i| return .{ .int = i } else |_| {}
            const f = std.fmt.parseFloat(f64, s) catch return null;
            return .{ .f = f };
        },
        else => return null,
    }
}

fn numToF64(n: Num) f64 {
    return switch (n) {
        .int => |i| @floatFromInt(i),
        .f => |f| f,
    };
}

fn numOrder(a: Num, b: Num) std.math.Order {
    if (a == .int and b == .int) return std.math.order(a.int, b.int);
    return std.math.order(numToF64(a), numToF64(b));
}

fn numIsInteger(n: Num) bool {
    return switch (n) {
        .int => true,
        .f => |f| std.math.isFinite(f) and f == @floor(f),
    };
}

/// Why an equality test stopped without an answer.
const EqlStop = error{
    /// The step budget ran out (one step per node compared).
    Budget,
    /// Both values nest deeper than `max_depth`.
    TooDeep,
};

/// JSON equality: numbers by value, objects regardless of member order.
/// Charges one budget step per node pair and stops at `max_depth`: the
/// values are the client's, and `uniqueItems` compares them with no schema
/// bounding their depth or size. Unbounded, two equal-shaped 200k-deep
/// arrays (under 1 MB on the wire) overflowed the stack, and 500 items of
/// 10k elements cost 1e9 compares inside a budget charged per pair
/// (review 2026-10-24).
fn jsonEql(budget: *Budget, a: std.json.Value, b: std.json.Value, depth: u32) EqlStop!bool {
    if (budget.left == 0) return error.Budget;
    budget.left -= 1;
    if (depth > max_depth) return error.TooDeep;
    if (toNum(a)) |x| {
        const y = toNum(b) orelse return false;
        return numOrder(x, y) == .eq;
    }
    switch (a) {
        .null => return b == .null,
        .bool => |x| return b == .bool and b.bool == x,
        .string => |x| return b == .string and std.mem.eql(u8, x, b.string),
        .array => |x| {
            if (b != .array or x.items.len != b.array.items.len) return false;
            for (x.items, b.array.items) |p, q| if (!try jsonEql(budget, p, q, depth + 1)) return false;
            return true;
        },
        .object => |x| {
            if (b != .object or x.count() != b.object.count()) return false;
            var it = x.iterator();
            while (it.next()) |e| {
                const other = b.object.get(e.key_ptr.*) orelse return false;
                if (!try jsonEql(budget, e.value_ptr.*, other, depth + 1)) return false;
            }
            return true;
        },
        else => return false,
    }
}

/// Unicode code points in UTF-8 `s`: every byte that is not a continuation.
fn codePoints(s: []const u8) usize {
    var n: usize = 0;
    for (s) |c| {
        if (c & 0xC0 != 0x80) n += 1;
    }
    return n;
}

fn typeName(v: std.json.Value) []const u8 {
    return switch (v) {
        .null => "null",
        .bool => "boolean",
        .integer, .float, .number_string => if (toNum(v)) |n| (if (numIsInteger(n)) "integer" else "number") else "number",
        .string => "string",
        .array => "array",
        .object => "object",
    };
}

fn typeMatches(name: []const u8, v: std.json.Value) bool {
    if (std.mem.eql(u8, name, "integer")) {
        const n = toNum(v) orelse return false;
        return numIsInteger(n);
    }
    if (std.mem.eql(u8, name, "number")) return toNum(v) != null;
    if (std.mem.eql(u8, name, "null")) return v == .null;
    if (std.mem.eql(u8, name, "boolean")) return v == .bool;
    if (std.mem.eql(u8, name, "object")) return v == .object;
    if (std.mem.eql(u8, name, "array")) return v == .array;
    if (std.mem.eql(u8, name, "string")) return v == .string;
    return false;
}

// ── validate ─────────────────────────────────────────────────────────────

/// One step of the path from the instance root, kept on the stack and only
/// turned into a JSON Pointer when a failure is built.
const Path = struct {
    parent: ?*const Path,
    seg: union(enum) { key: []const u8, index: usize },
};

const Budget = struct {
    left: u32,
    /// Set once, where the budget ran out.
    pointer: ?[]const u8 = null,
};

const Checker = struct {
    arena: std.mem.Allocator,
    root: std.json.Value,
    budget: *Budget,
    /// Inside a branch whose failure is thrown away (anyOf / oneOf / not / the
    /// `if` condition) only "it failed" matters, so `fail` builds no pointer or
    /// message: the arena grows with the number of REPORTED failures, not with
    /// branches x path length (no-panic sweep 2026-10-28 M-1).
    quiet: bool = false,

    fn quieted(c: Checker) Checker {
        var q = c;
        q.quiet = true;
        return q;
    }

    fn fail(c: Checker, path: ?*const Path, keyword: []const u8, comptime fmt: []const u8, args: anytype) error{OutOfMemory}!?Failure {
        if (c.quiet) return Failure{ .pointer = "", .keyword = keyword, .message = "" };
        return Failure{
            .pointer = try pointerOf(c.arena, path),
            .keyword = keyword,
            .message = try std.fmt.allocPrint(c.arena, fmt, args),
        };
    }

    /// Charge `n` steps; the budget failure once it is spent.
    fn spend(c: Checker, n: usize, path: ?*const Path) error{OutOfMemory}!?Failure {
        if (c.budget.left < n) {
            c.budget.left = 0;
            if (c.budget.pointer == null) c.budget.pointer = try pointerOf(c.arena, path);
            return Failure{ .pointer = c.budget.pointer.?, .keyword = "budget", .message = "schema check exceeded its step budget" };
        }
        c.budget.left -= @intCast(n);
        return null;
    }

    /// `jsonEql` under this check's budget; a stop is the failure it reports.
    fn eql(c: Checker, a: std.json.Value, b: std.json.Value, path: ?*const Path, depth: u32) error{OutOfMemory}!union(enum) { same: bool, failure: Failure } {
        const same = jsonEql(c.budget, a, b, depth) catch |e| return .{ .failure = switch (e) {
            error.Budget => (try c.spend(1, path)).?,
            error.TooDeep => (try c.fail(path, "depth", "nesting deeper than {d} levels", .{@as(u32, max_depth)})).?,
        } };
        return .{ .same = same };
    }

    fn apply(c: Checker, schema: std.json.Value, inst: std.json.Value, path: ?*const Path, depth: u32, refs: u32) error{OutOfMemory}!?Failure {
        if (try c.spend(1, path)) |f| return f;
        if (depth > max_depth) return c.fail(path, "depth", "nesting deeper than {d} levels", .{@as(u32, max_depth)});
        switch (schema) {
            .bool => |b| {
                if (b) return null;
                return c.fail(path, "false", "no value is valid here", .{});
            },
            .object => |o| return c.applyObject(o, inst, path, depth, refs),
            else => return null,
        }
    }

    fn applyObject(c: Checker, o: std.json.ObjectMap, inst: std.json.Value, path: ?*const Path, depth: u32, refs: u32) error{OutOfMemory}!?Failure {
        if (o.get("$ref")) |r| {
            if (refs >= max_ref_depth) return c.fail(path, "$ref", "reference depth limit {d} exceeded", .{@as(u32, max_ref_depth)});
            if (r == .string) {
                if (resolveRef(c.root, r.string)) |target| {
                    if (try c.apply(target, inst, path, depth + 1, refs + 1)) |f| return f;
                }
            }
        }
        if (o.get("type")) |t| {
            const ok = switch (t) {
                .string => |s| typeMatches(s, inst),
                .array => |a| blk: {
                    for (a.items) |x| if (x == .string and typeMatches(x.string, inst)) break :blk true;
                    break :blk false;
                },
                else => true,
            };
            if (!ok) return c.fail(path, "type", "expected {s}, got {s}", .{ typeLabel(t), typeName(inst) });
        }
        if (o.get("enum")) |e| {
            if (e == .array) {
                var found = false;
                for (e.array.items) |x| switch (try c.eql(x, inst, path, depth)) {
                    .failure => |f| return f,
                    .same => |same| if (same) {
                        found = true;
                        break;
                    },
                };
                if (!found) return c.fail(path, "enum", "value is not one of the allowed values", .{});
            }
        }
        if (o.get("const")) |k| {
            switch (try c.eql(k, inst, path, depth)) {
                .failure => |f| return f,
                .same => |same| if (!same) return c.fail(path, "const", "value does not equal the required constant", .{}),
            }
        }
        if (toNum(inst)) |n| {
            if (try c.numeric(o, n, path)) |f| return f;
        }
        switch (inst) {
            .string => |s| if (try c.string(o, s, path)) |f| return f,
            .array => |a| if (try c.array(o, a.items, path, depth, refs)) |f| return f,
            .object => |m| if (try c.object(o, m, path, depth, refs)) |f| return f,
            else => {},
        }
        if (try c.combinators(o, inst, path, depth, refs)) |f| return f;
        return null;
    }

    fn numeric(c: Checker, o: std.json.ObjectMap, n: Num, path: ?*const Path) error{OutOfMemory}!?Failure {
        const x = numToF64(n);
        if (o.get("minimum")) |l| if (toNum(l)) |lim| {
            if (numOrder(n, lim) == .lt) return c.fail(path, "minimum", "{d} is less than the minimum {d}", .{ x, numToF64(lim) });
        };
        if (o.get("exclusiveMinimum")) |l| if (toNum(l)) |lim| {
            if (numOrder(n, lim) != .gt) return c.fail(path, "exclusiveMinimum", "{d} is not greater than {d}", .{ x, numToF64(lim) });
        };
        if (o.get("maximum")) |l| if (toNum(l)) |lim| {
            if (numOrder(n, lim) == .gt) return c.fail(path, "maximum", "{d} is greater than the maximum {d}", .{ x, numToF64(lim) });
        };
        if (o.get("exclusiveMaximum")) |l| if (toNum(l)) |lim| {
            if (numOrder(n, lim) != .lt) return c.fail(path, "exclusiveMaximum", "{d} is not less than {d}", .{ x, numToF64(lim) });
        };
        if (o.get("multipleOf")) |d| if (toNum(d)) |div| {
            if (!isMultiple(n, div)) return c.fail(path, "multipleOf", "{d} is not a multiple of {d}", .{ x, numToF64(div) });
        };
        return null;
    }

    fn string(c: Checker, o: std.json.ObjectMap, s: []const u8, path: ?*const Path) error{OutOfMemory}!?Failure {
        // `pattern` is deliberately not checked (no regex engine here).
        if (o.get("minLength")) |l| if (asCount(l)) |lim| {
            const n = codePoints(s);
            if (n < lim) return c.fail(path, "minLength", "string has {d} characters, at least {d} required", .{ n, lim });
        };
        if (o.get("maxLength")) |l| if (asCount(l)) |lim| {
            const n = codePoints(s);
            if (n > lim) return c.fail(path, "maxLength", "string has {d} characters, at most {d} allowed", .{ n, lim });
        };
        return null;
    }

    fn array(c: Checker, o: std.json.ObjectMap, items: []const std.json.Value, path: ?*const Path, depth: u32, refs: u32) error{OutOfMemory}!?Failure {
        if (o.get("minItems")) |l| if (asCount(l)) |lim| {
            if (items.len < lim) return c.fail(path, "minItems", "array has {d} items, at least {d} required", .{ items.len, lim });
        };
        if (o.get("maxItems")) |l| if (asCount(l)) |lim| {
            if (items.len > lim) return c.fail(path, "maxItems", "array has {d} items, at most {d} allowed", .{ items.len, lim });
        };
        if (o.get("uniqueItems")) |u| if (u == .bool and u.bool) {
            for (items, 0..) |a, i| {
                // Pairwise is O(n²): every comparison is a step, so a hostile
                // array of a million items ends in the budget, not a hang.
                if (try c.spend(i, path)) |f| return f;
                for (items[0..i]) |b| {
                    const here: Path = .{ .parent = path, .seg = .{ .index = i } };
                    switch (try c.eql(a, b, &here, depth + 1)) {
                        .failure => |f| return f,
                        .same => |same| if (same) return c.fail(&here, "uniqueItems", "item is a duplicate of an earlier item", .{}),
                    }
                }
            }
        };
        var prefix_len: usize = 0;
        if (o.get("prefixItems")) |p| if (p == .array) {
            prefix_len = p.array.items.len;
            for (items[0..@min(items.len, prefix_len)], p.array.items[0..@min(items.len, prefix_len)], 0..) |item, sub, i| {
                const here: Path = .{ .parent = path, .seg = .{ .index = i } };
                if (try c.apply(sub, item, &here, depth + 1, refs)) |f| return f;
            }
        };
        if (o.get("items")) |sub| {
            var i = prefix_len;
            while (i < items.len) : (i += 1) {
                const here: Path = .{ .parent = path, .seg = .{ .index = i } };
                if (try c.apply(sub, items[i], &here, depth + 1, refs)) |f| return f;
            }
        }
        return null;
    }

    fn object(c: Checker, o: std.json.ObjectMap, m: std.json.ObjectMap, path: ?*const Path, depth: u32, refs: u32) error{OutOfMemory}!?Failure {
        if (o.get("minProperties")) |l| if (asCount(l)) |lim| {
            if (m.count() < lim) return c.fail(path, "minProperties", "object has {d} properties, at least {d} required", .{ m.count(), lim });
        };
        if (o.get("maxProperties")) |l| if (asCount(l)) |lim| {
            if (m.count() > lim) return c.fail(path, "maxProperties", "object has {d} properties, at most {d} allowed", .{ m.count(), lim });
        };
        if (o.get("required")) |r| if (r == .array) {
            for (r.array.items) |name| {
                if (name == .string and !m.contains(name.string)) {
                    return c.fail(path, "required", "missing required property \"{s}\"", .{name.string});
                }
            }
        };
        const props: ?std.json.ObjectMap = if (o.get("properties")) |p| (if (p == .object) p.object else null) else null;
        if (props) |p| {
            var it = p.iterator();
            while (it.next()) |e| {
                const val = m.get(e.key_ptr.*) orelse continue;
                const here: Path = .{ .parent = path, .seg = .{ .key = e.key_ptr.* } };
                if (try c.apply(e.value_ptr.*, val, &here, depth + 1, refs)) |f| return f;
            }
        }
        if (o.get("additionalProperties")) |ap| {
            var it = m.iterator();
            while (it.next()) |e| {
                if (props) |p| if (p.contains(e.key_ptr.*)) continue;
                const here: Path = .{ .parent = path, .seg = .{ .key = e.key_ptr.* } };
                if (ap == .bool and !ap.bool) {
                    return c.fail(&here, "additionalProperties", "additional property \"{s}\" is not allowed", .{e.key_ptr.*});
                }
                if (try c.apply(ap, e.value_ptr.*, &here, depth + 1, refs)) |f| return f;
            }
        }
        return null;
    }

    fn combinators(c: Checker, o: std.json.ObjectMap, inst: std.json.Value, path: ?*const Path, depth: u32, refs: u32) error{OutOfMemory}!?Failure {
        if (o.get("allOf")) |l| if (l == .array) {
            for (l.array.items) |sub| {
                if (try c.apply(sub, inst, path, depth + 1, refs)) |f| return f;
            }
        };
        const q = c.quieted();
        if (o.get("anyOf")) |l| if (l == .array) {
            var any = false;
            for (l.array.items) |sub| {
                if (try q.apply(sub, inst, path, depth + 1, refs) == null) {
                    any = true;
                    break;
                }
            }
            if (!any) return c.fail(path, "anyOf", "value matches none of the anyOf schemas", .{});
        };
        if (o.get("oneOf")) |l| if (l == .array) {
            var matched: usize = 0;
            for (l.array.items) |sub| {
                if (try q.apply(sub, inst, path, depth + 1, refs) == null) matched += 1;
            }
            if (matched == 0) return c.fail(path, "oneOf", "value matches none of the oneOf schemas", .{});
            if (matched > 1) return c.fail(path, "oneOf", "value matches {d} of the oneOf schemas, exactly one required", .{matched});
        };
        if (o.get("not")) |sub| {
            if (try q.apply(sub, inst, path, depth + 1, refs) == null) {
                return c.fail(path, "not", "value matches the schema it must not match", .{});
            }
        }
        if (o.get("if")) |cond| {
            const branch = if (try q.apply(cond, inst, path, depth + 1, refs) == null) o.get("then") else o.get("else");
            if (branch) |b| {
                if (try c.apply(b, inst, path, depth + 1, refs)) |f| return f;
            }
        }
        return null;
    }
};

fn isMultiple(n: Num, d: Num) bool {
    if (n == .int and d == .int) {
        if (d.int == 0) return false;
        return @rem(n.int, d.int) == 0;
    }
    // A decimal divisor is not exact in binary (0.07 / 0.01 is
    // 7.000000000000001), so the quotient counts as whole when it is within a
    // relative 1e-9 of an integer — more lenient than ajv's and Python
    // jsonschema's default (both refuse 0.07 for multipleOf 0.01), deliberately:
    // a refusal here turns away a value the schema's author meant to allow.
    const q = numToF64(n) / numToF64(d);
    if (!std.math.isFinite(q)) return false;
    const r = @round(q);
    return @abs(q - r) <= 1e-9 * @max(1.0, @abs(q));
}

/// `type`'s expected value for a message: the name, or the names joined by `|`.
fn typeLabel(t: std.json.Value) []const u8 {
    return switch (t) {
        .string => |s| s,
        else => "one of the allowed types",
    };
}

/// RFC 6901 pointer for `path` (`""` for the root), `~` as `~0`, `/` as `~1`.
fn pointerOf(arena: std.mem.Allocator, path: ?*const Path) error{OutOfMemory}![]const u8 {
    var segs: std.ArrayList(*const Path) = .empty;
    var p = path;
    while (p) |node| : (p = node.parent) try segs.append(arena, node);
    var out: std.ArrayList(u8) = .empty;
    var i = segs.items.len;
    while (i > 0) {
        i -= 1;
        try out.append(arena, '/');
        switch (segs.items[i].seg) {
            .key => |k| for (k) |ch| switch (ch) {
                '~' => try out.appendSlice(arena, "~0"),
                '/' => try out.appendSlice(arena, "~1"),
                else => try out.append(arena, ch),
            },
            .index => |n| try out.appendSlice(arena, try std.fmt.allocPrint(arena, "{d}", .{n})),
        }
    }
    return out.items;
}

// ── tests ────────────────────────────────────────────────────────────────

const testing = std.testing;
const vectors = @import("schema_suite_vectors.zig");

/// Parses `schema_text`, compiles it, validates `instance_text`.
fn run(arena: std.mem.Allocator, schema_text: []const u8, instance_text: []const u8) !?Failure {
    const sv = try std.json.parseFromSliceLeaky(std.json.Value, arena, schema_text, .{});
    const iv = try std.json.parseFromSliceLeaky(std.json.Value, arena, instance_text, .{});
    const s = try Schema.compile(arena, sv);
    return try s.validate(arena, iv);
}

test "JSON-Schema-Test-Suite vectors give the suite's verdict" {
    var arena_state: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena_state.deinit();
    var bad: usize = 0;
    for (vectors.cases) |case| {
        _ = arena_state.reset(.retain_capacity);
        const arena = arena_state.allocator();
        const got = run(arena, case.schema, case.data) catch |err| {
            std.debug.print("suite {s}: \"{s}\": error {s}\n", .{ case.file, case.description, @errorName(err) });
            bad += 1;
            continue;
        };
        if ((got == null) != case.valid) {
            std.debug.print("suite {s}: \"{s}\": want valid={}, got {s}\n  schema: {s}\n  data: {s}\n", .{
                case.file,
                case.description,
                case.valid,
                if (got) |f| f.keyword else "valid",
                case.schema,
                case.data,
            });
            bad += 1;
        }
    }
    try testing.expectEqual(@as(usize, 0), bad);
    try testing.expect(vectors.cases.len > 100);
}

test "failure pointer and keyword: nested objects and arrays" {
    var arena_state: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena_state.deinit();
    const a = arena_state.allocator();
    const schema =
        \\{"type":"object","required":["user"],"properties":{
        \\  "user":{"type":"object","properties":{
        \\    "tags":{"type":"array","items":{"type":"string"}},
        \\    "a/b":{"type":"object","properties":{"m~n":{"type":"integer"}}}},
        \\   "additionalProperties":false}}}
    ;
    const f1 = (try run(a, schema, "{\"user\":{\"tags\":[\"x\",\"y\",3]}}")).?;
    try testing.expectEqualStrings("/user/tags/2", f1.pointer);
    try testing.expectEqualStrings("type", f1.keyword);
    const f2 = (try run(a, schema, "{\"user\":{\"a/b\":{\"m~n\":\"s\"}}}")).?;
    try testing.expectEqualStrings("/user/a~1b/m~0n", f2.pointer);
    const f3 = (try run(a, schema, "{}")).?;
    try testing.expectEqualStrings("", f3.pointer);
    try testing.expectEqualStrings("required", f3.keyword);
    const f4 = (try run(a, schema, "{\"user\":{\"extra\":1}}")).?;
    try testing.expectEqualStrings("/user/extra", f4.pointer);
    try testing.expectEqualStrings("additionalProperties", f4.keyword);
    try testing.expect((try run(a, schema, "{\"user\":{\"tags\":[]}}")) == null);
}

test "prefixItems and items: the tail after the prefix" {
    var arena_state: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena_state.deinit();
    const a = arena_state.allocator();
    const schema = "{\"prefixItems\":[{\"type\":\"string\"},{\"type\":\"boolean\"}],\"items\":{\"type\":\"integer\"}}";
    try testing.expect((try run(a, schema, "[\"a\",true,1,2]")) == null);
    const f = (try run(a, schema, "[\"a\",true,1,\"z\"]")).?;
    try testing.expectEqualStrings("/3", f.pointer);
    const g = (try run(a, schema, "[\"a\",5]")).?;
    try testing.expectEqualStrings("/1", g.pointer);
}

test "$ref cycle stops at the depth cap instead of looping" {
    var arena_state: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena_state.deinit();
    const a = arena_state.allocator();
    const f = (try run(a, "{\"$ref\":\"#\"}", "1")).?;
    try testing.expectEqualStrings("$ref", f.keyword);
    const g = (try run(a, "{\"$defs\":{\"x\":{\"$ref\":\"#/$defs/y\"},\"y\":{\"$ref\":\"#/$defs/x\"}},\"$ref\":\"#/$defs/x\"}", "null")).?;
    try testing.expectEqualStrings("$ref", g.keyword);
    // A legitimate recursion well under the cap.
    const tree = "{\"$defs\":{\"n\":{\"type\":\"object\",\"properties\":{\"kids\":{\"type\":\"array\",\"items\":{\"$ref\":\"#/$defs/n\"}}}}},\"$ref\":\"#/$defs/n\"}";
    try testing.expect((try run(a, tree, "{\"kids\":[{\"kids\":[{}]}]}")) == null);
    const bad = (try run(a, tree, "{\"kids\":[{\"kids\":[7]}]}")).?;
    try testing.expectEqualStrings("/kids/0/kids/0", bad.pointer);
}

test "$ref forms: escapes and refusals" {
    var arena_state: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena_state.deinit();
    const a = arena_state.allocator();
    try testing.expect((try run(a, "{\"definitions\":{\"a/b~c\":{\"type\":\"string\"}},\"$ref\":\"#/definitions/a~1b~0c\"}", "\"s\"")) == null);
    try testing.expect((try run(a, "{\"$defs\":{\"a b\":{\"type\":\"string\"}},\"$ref\":\"#/$defs/a%20b\"}", "1")) != null);
    const refuse = [_][]const u8{
        "{\"$ref\":\"#/$defs/missing\"}",
        "{\"$ref\":\"http://example.com/x\"}",
        "{\"$ref\":\"other.json\"}",
        "{\"properties\":{\"a\":{\"type\":\"string\"}},\"$ref\":\"#/properties/a\"}",
        "{\"$defs\":{\"a\":{\"properties\":{}}},\"$ref\":\"#/$defs/a/properties\"}",
    };
    for (refuse) |text| {
        const v = try std.json.parseFromSliceLeaky(std.json.Value, a, text, .{});
        try testing.expectError(error.BadRef, Schema.compile(a, v));
    }
}

test "maxLength counts code points, not bytes" {
    var arena_state: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena_state.deinit();
    const a = arena_state.allocator();
    // U+1F4A9 is four UTF-8 bytes and one code point; "é" is two bytes.
    try testing.expect((try run(a, "{\"maxLength\":1}", "\"\u{1F4A9}\"")) == null);
    try testing.expect((try run(a, "{\"maxLength\":2}", "\"\u{1F4A9}\u{E9}\"")) == null);
    const f = (try run(a, "{\"maxLength\":2}", "\"\u{1F4A9}\u{E9}x\"")).?;
    try testing.expectEqualStrings("maxLength", f.keyword);
    try testing.expect((try run(a, "{\"minLength\":2}", "\"\u{1F4A9}\"")) != null);
    try testing.expect((try run(a, "{\"minLength\":2}", "\"\u{1F4A9}\u{1F4A9}\"")) == null);
}

test "integer: 1.0 is an integer, 1.5 is not" {
    var arena_state: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena_state.deinit();
    const a = arena_state.allocator();
    try testing.expect((try run(a, "{\"type\":\"integer\"}", "1.0")) == null);
    try testing.expect((try run(a, "{\"type\":\"integer\"}", "1e2")) == null);
    try testing.expect((try run(a, "{\"type\":\"integer\"}", "1.5")) != null);
    try testing.expect((try run(a, "{\"type\":[\"integer\",\"null\"]}", "null")) == null);
    try testing.expect((try run(a, "{\"type\":\"number\"}", "1")) == null);
    try testing.expect((try run(a, "{\"enum\":[1]}", "1.0")) == null);
    try testing.expect((try run(a, "{\"uniqueItems\":true}", "[1,1.0]")) != null);
    try testing.expect((try run(a, "{\"uniqueItems\":true}", "[{\"a\":1,\"b\":2},{\"b\":2,\"a\":1.0}]")) != null);
}

test "compile refuses what it cannot check, accepts annotations" {
    var arena_state: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena_state.deinit();
    const a = arena_state.allocator();
    const P = std.json.parseFromSliceLeaky;
    const unsupported = [_][]const u8{
        "{\"patternProperties\":{\"^a\":{}}}",
        "{\"contains\":{}}",
        "{\"dependentRequired\":{}}",
        "{\"properties\":{\"a\":{\"$id\":\"x\"}}}",
        "{\"$anchor\":\"a\"}",
    };
    for (unsupported) |t| {
        const v = try P(std.json.Value, a, t, .{});
        try testing.expectError(error.UnsupportedKeyword, Schema.compile(a, v));
    }
    const wrong = [_][]const u8{ "{\"required\":3}", "{\"type\":\"nope\"}", "{\"minItems\":-1}", "{\"items\":[{}]}", "{\"multipleOf\":0}" };
    for (wrong) |t| {
        const v = try P(std.json.Value, a, t, .{});
        try testing.expectError(error.BadKeywordValue, Schema.compile(a, v));
    }
    try testing.expectError(error.SchemaNotObject, Schema.compile(a, .{ .integer = 1 }));
    const ok = try P(std.json.Value, a,
        \\{"$schema":"https://json-schema.org/draft/2020-12/schema","$id":"urn:x","title":"t","description":"d",
        \\ "type":"object","x-mcp-header":"H","$comment":"c","default":{},"examples":[{}],
        \\ "properties":{"a":{"type":"string","format":"email","pattern":"^a","x-foo":1,"deprecated":true}}}
    , .{});
    const s = try Schema.compile(a, ok);
    // `pattern` is not checked: a value that violates it is valid here.
    const inst = try P(std.json.Value, a, "{\"a\":\"zzz\"}", .{});
    try testing.expect((try s.validate(a, inst)) == null);
}

test "composition and conditionals report the right keyword" {
    var arena_state: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena_state.deinit();
    const a = arena_state.allocator();
    const one = "{\"oneOf\":[{\"type\":\"integer\"},{\"minimum\":0}]}";
    try testing.expectEqualStrings("oneOf", (try run(a, one, "5")).?.keyword);
    try testing.expect((try run(a, one, "-5")) == null);
    try testing.expectEqualStrings("not", (try run(a, "{\"not\":{\"type\":\"string\"}}", "\"s\"")).?.keyword);
    const cond = "{\"if\":{\"properties\":{\"k\":{\"const\":1}}},\"then\":{\"required\":[\"x\"]},\"else\":{\"required\":[\"y\"]}}";
    const then_fail = (try run(a, cond, "{\"k\":1}")).?;
    try testing.expectEqualStrings("required", then_fail.keyword);
    try testing.expect(std.mem.find(u8, then_fail.message, "\"x\"") != null);
    try testing.expect((try run(a, cond, "{\"k\":2,\"y\":0}")) == null);
}

test "multipleOf: exact for integers, finite quotient otherwise" {
    var arena_state: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena_state.deinit();
    const a = arena_state.allocator();
    // 2^53 + 1 is a multiple of 3, 2^53 is not; an f64 quotient could not tell.
    try testing.expect((try run(a, "{\"multipleOf\":3}", "9007199254740993")) == null);
    try testing.expect((try run(a, "{\"multipleOf\":3}", "9007199254740992")) != null);
    try testing.expect((try run(a, "{\"multipleOf\":0.5}", "4.5")) == null);
    try testing.expect((try run(a, "{\"multipleOf\":0.123456789}", "1e308")) != null);
}

test "multipleOf: a decimal divisor accepts what it means (review 2026-10-20 M2)" {
    var arena_state: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena_state.deinit();
    const a = arena_state.allocator();
    // 0.07 / 0.01 = 7.000000000000001 and 19.99 / 0.01 = 1998.9999999999998 in f64.
    try testing.expect((try run(a, "{\"multipleOf\":0.01}", "0.07")) == null);
    try testing.expect((try run(a, "{\"multipleOf\":0.01}", "19.99")) == null);
    try testing.expect((try run(a, "{\"multipleOf\":0.05}", "1.15")) == null);
    try testing.expect((try run(a, "{\"multipleOf\":0.01}", "0.075")) != null);
}

test "uniqueItems: a long array spends the budget instead of hanging (review 2026-10-20 M1)" {
    var arena_state: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena_state.deinit();
    const a = arena_state.allocator();
    var text: std.ArrayList(u8) = .empty;
    try text.append(a, '[');
    for (0..20000) |i| try text.print(a, "{s}{d}", .{ if (i == 0) "" else ",", i });
    try text.append(a, ']');
    const sv = try std.json.parseFromSliceLeaky(std.json.Value, a, "{\"uniqueItems\":true}", .{});
    const s = try Schema.compile(a, sv);
    const iv = try std.json.parseFromSliceLeaky(std.json.Value, a, text.items, .{});
    // 20000 items = 2e8 comparisons, far past the default budget of 1e6.
    const f = (try s.validate(a, iv)).?;
    try testing.expectEqualStrings("budget", f.keyword);
    // A short one is checked in full.
    const small = try std.json.parseFromSliceLeaky(std.json.Value, a, "[1,2,3,2]", .{});
    try testing.expectEqualStrings("uniqueItems", (try s.validate(a, small)).?.keyword);
}

test "uniqueItems over deep or large items: a failure, never a stack overflow or 1e9 compares (review 2026-10-24)" {
    var arena_state: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena_state.deinit();
    const a = arena_state.allocator();
    const sv = try std.json.parseFromSliceLeaky(std.json.Value, a, "{\"uniqueItems\":true}", .{});
    const s = try Schema.compile(a, sv);

    // Two equal-shaped 200k-deep arrays: std.json builds them iteratively; the
    // equality test used to recurse once per level.
    var deep: std.ArrayList(u8) = .empty;
    try deep.append(a, '[');
    for (0..2) |k| {
        if (k > 0) try deep.append(a, ',');
        try deep.appendNTimes(a, '[', 200_000);
        try deep.appendNTimes(a, ']', 200_000);
    }
    try deep.append(a, ']');
    const dv = try std.json.parseFromSliceLeaky(std.json.Value, a, deep.items, .{});
    try testing.expectEqualStrings("depth", (try s.validate(a, dv)).?.keyword);

    // 300 items of 5000 elements differing only in the last: the budget was
    // charged per pair, not per element compared.
    var wide: std.ArrayList(u8) = .empty;
    try wide.append(a, '[');
    for (0..300) |k| {
        if (k > 0) try wide.append(a, ',');
        try wide.append(a, '[');
        for (0..4999) |_| try wide.appendSlice(a, "1,");
        try wide.print(a, "{d}]", .{k});
    }
    try wide.append(a, ']');
    const wv = try std.json.parseFromSliceLeaky(std.json.Value, a, wide.items, .{});
    try testing.expectEqualStrings("budget", (try s.validate(a, wv)).?.keyword);

    // `const`/`enum` share the bound.
    const cv = try std.json.parseFromSliceLeaky(std.json.Value, a, "{\"const\":[[[1]]]}", .{});
    const cs = try Schema.compile(a, cv);
    try testing.expect((try cs.validate(a, try std.json.parseFromSliceLeaky(std.json.Value, a, "[[[1]]]", .{}))) == null);
    try testing.expectEqualStrings("const", (try cs.validate(a, try std.json.parseFromSliceLeaky(std.json.Value, a, "[[[2]]]", .{}))).?.keyword);
}

test "deeply nested instance is a failure, not a stack overflow" {
    var arena_state: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena_state.deinit();
    const a = arena_state.allocator();
    var text: std.ArrayList(u8) = .empty;
    for (0..100) |_| try text.append(a, '[');
    for (0..100) |_| try text.append(a, ']');
    const sv = try std.json.parseFromSliceLeaky(std.json.Value, a, "{\"$defs\":{\"r\":{\"items\":{\"$ref\":\"#/$defs/r\"}}},\"$ref\":\"#/$defs/r\"}", .{});
    const s = try Schema.compile(a, sv);
    const iv = try std.json.parseFromSliceLeaky(std.json.Value, a, text.items, .{});
    const f = (try s.validate(a, iv)).?;
    try testing.expect(std.mem.eql(u8, f.keyword, "depth") or std.mem.eql(u8, f.keyword, "$ref"));
}

test "step budget: exponential anyOf recursion ends in a budget failure" {
    var arena_state: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena_state.deinit();
    const a = arena_state.allocator();
    const schema =
        \\{"$defs":{"n":{"anyOf":[
        \\ {"type":"object","properties":{"c":{"$ref":"#/$defs/n"}},"allOf":[{"required":["x"]}]},
        \\ {"type":"object","properties":{"c":{"$ref":"#/$defs/n"}}}]}},"$ref":"#/$defs/n"}
    ;
    const sv = try std.json.parseFromSliceLeaky(std.json.Value, a, schema, .{});
    const s = try Schema.compile(a, sv);
    // Branch 1 recurses into "c" and only then fails (`allOf` is checked after
    // `properties`), so every level costs two sub-validations.
    // Depth 5 is valid and far below the default budget.
    const small = try nested(a, 5, true);
    try testing.expect((try s.validate(a, small)) == null);
    // Depth 40 would take ~2^40 steps; the budget cuts it short. The innermost
    // object is invalid in branch 1 (no "x") and valid in branch 2, so the
    // instance is valid, yet the verdict here is "budget".
    const deep = try nested(a, 40, true);
    const f = (try s.validate(a, deep)).?;
    try testing.expectEqualStrings("budget", f.keyword);
    // A lowered budget trips on a small instance, and the default does not.
    const g = (try s.validateBudget(a, small, 3)).?;
    try testing.expectEqualStrings("budget", g.keyword);
}

/// `{"c":{"c":...{}}}`, `depth` levels of "c".
fn nested(a: std.mem.Allocator, depth: usize, _: bool) !std.json.Value {
    var text: std.ArrayList(u8) = .empty;
    for (0..depth) |_| try text.appendSlice(a, "{\"c\":");
    try text.appendSlice(a, "{}");
    for (0..depth) |_| try text.append(a, '}');
    return std.json.parseFromSliceLeaky(std.json.Value, a, text.items, .{});
}

test "sweep 2026-10-28 M-1: discarded anyOf/oneOf/not/if failures build no pointer strings" {
    var arena_state: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena_state.deinit();
    const a = arena_state.allocator();
    const key = try a.alloc(u8, 64 * 1024);
    @memset(key, 'k');
    // 20 branches each failing at `/<64 KiB key>`, in every discarding keyword.
    var branches: std.ArrayList(u8) = .empty;
    for (0..20) |i| {
        if (i != 0) try branches.append(a, ',');
        try branches.print(a, "{{\"properties\":{{\"{s}\":{{\"type\":\"string\"}}}}}}", .{key});
    }
    const inst_text = try std.fmt.allocPrint(a, "{{\"{s}\":1}}", .{key});
    const inst = try std.json.parseFromSliceLeaky(std.json.Value, a, inst_text, .{});
    for ([_][]const u8{ "anyOf", "oneOf" }) |kw| {
        const schema_text = try std.fmt.allocPrint(a, "{{\"{s}\":[{s}]}}", .{ kw, branches.items });
        var scratch: std.heap.ArenaAllocator = .init(testing.allocator);
        defer scratch.deinit();
        const sv = try std.json.parseFromSliceLeaky(std.json.Value, scratch.allocator(), schema_text, .{});
        const s = try Schema.compile(scratch.allocator(), sv);
        var out: std.heap.ArenaAllocator = .init(testing.allocator);
        defer out.deinit();
        const f = (try s.validate(out.allocator(), inst)).?;
        try testing.expectEqualStrings(kw, f.keyword);
        try testing.expectEqualStrings("", f.pointer);
        try testing.expect(out.queryCapacity() < 16 * 1024);
    }
    // `not` and `if`: one discarded branch each; the verdicts are unchanged.
    var out: std.heap.ArenaAllocator = .init(testing.allocator);
    defer out.deinit();
    const not_text = try std.fmt.allocPrint(a, "{{\"not\":{{\"properties\":{{\"{s}\":{{\"type\":\"integer\"}}}}}}}}", .{key});
    const ns = try Schema.compile(a, try std.json.parseFromSliceLeaky(std.json.Value, a, not_text, .{}));
    try testing.expectEqualStrings("not", (try ns.validate(out.allocator(), inst)).?.keyword);
    const if_text = try std.fmt.allocPrint(a, "{{\"if\":{{\"properties\":{{\"{s}\":{{\"type\":\"string\"}}}}}},\"else\":{{\"required\":[\"zz\"]}}}}", .{key});
    const is = try Schema.compile(a, try std.json.parseFromSliceLeaky(std.json.Value, a, if_text, .{}));
    try testing.expectEqualStrings("required", (try is.validate(out.allocator(), inst)).?.keyword);
    try testing.expect(out.queryCapacity() < 16 * 1024);
}
