// SPDX-License-Identifier: MIT
//! Typed mapping: YAML onto Zig types (`parse`, `fromValue`) and Zig values
//! back into a `Value` (`toValue`) for the emitter — what `std.json`'s
//! `parseFromSlice` / `Stringify` are to JSON.
//!
//! | Zig type          | YAML                                                        |
//! |-------------------|-------------------------------------------------------------|
//! | `bool`            | `true` / `false` (1.2 core: never `yes` / `no`)              |
//! | integers          | an int, range-checked (`error.Overflow`)                    |
//! | `f32` / `f64`     | a float, or an int that the float holds exactly             |
//! | `[]const u8`      | a string — never a number or bool spelled in the source     |
//! | `[]const T`, `[N]T` | a sequence (`[N]T`: exactly N items)                     |
//! | tuple             | a sequence of exactly that many items                       |
//! | `struct`          | a mapping with string keys: field names, or `yaml_keys`     |
//! | `?T`              | `null` (or an absent key) ↔ `null`                          |
//! | `enum`            | its tag name, as a string                                   |
//! | `union(enum)`     | a one-pair mapping `{variant: payload}`; a `void` variant may also be the bare string |
//! | `*const T`        | the `T` it points to                                        |
//! | `yaml.Value`      | the node as is                                              |
//!
//! A struct may rename keys: `pub const yaml_keys = .{ .max_conn = "max-connections" };`
//! (YAML configs are kebab-case, Zig fields are not). Decode rules: a missing
//! key takes the field's default, or `null` if optional, else
//! `error.MissingField`; an unknown key is skipped unless
//! `Options.ignore_unknown_fields = false` (`error.UnknownField`).
//!
//! The strictness is deliberate: a `[]const u8` field fed `version: 1.10`
//! is `error.WrongType`, not `"1.1"` — the core schema already read `1.10`
//! as the float 1.1, and quietly re-spelling it is the classic YAML bug.
//! Quote it in the document.
//!
//! **Memory.** `parse` returns a `Parsed(T)` owning an arena with the composed
//! tree and everything `T` points into; `fromValue` allocates into the arena
//! you pass and may alias the `Value`. What the mapping itself allocates is
//! capped by `Options.max_alloc_bytes` (`error.TooLarge`): an alias lets a
//! small document name a large node many times, and a `[]const T` element can
//! be much larger than its node.

const std = @import("std");
const compose = @import("compose.zig");
const Value = compose.Value;
const Pair = compose.Pair;
const Allocator = std.mem.Allocator;

pub const Error = compose.Error || error{
    ExpectedSingleDocument,
    WrongType,
    Overflow,
    MissingField,
    UnknownField,
    DuplicateField,
    LengthMismatch,
    InvalidEnum,
    TooLarge,
};

pub const Options = struct {
    compose: compose.Options = .{},
    ignore_unknown_fields: bool = true,
    max_alloc_bytes: usize = 64 << 20,
};

pub fn Parsed(comptime T: type) type {
    return struct {
        arena: *std.heap.ArenaAllocator,
        value: T,

        pub fn deinit(self: @This()) void {
            const gpa = self.arena.child_allocator;
            self.arena.deinit();
            gpa.destroy(self.arena);
        }
    };
}

/// Compose `source` (exactly one document) and map it onto `T`.
pub fn parse(comptime T: type, gpa: Allocator, source: []const u8, options: Options) Error!Parsed(T) {
    const arena = try gpa.create(std.heap.ArenaAllocator);
    errdefer gpa.destroy(arena);
    arena.* = .init(gpa);
    errdefer arena.deinit();
    const a = arena.allocator();
    const docs = try compose.composeAllLeaky(a, source, options.compose);
    if (docs.len != 1) return error.ExpectedSingleDocument;
    return .{ .arena = arena, .value = try fromValue(T, a, docs[0], options) };
}

pub fn fromValue(comptime T: type, arena: Allocator, v: Value, options: Options) Error!T {
    var budget = options.max_alloc_bytes;
    return into(T, arena, v, options, &budget);
}

fn charge(budget: *usize, size: usize, n: usize) Error!void {
    const total = std.math.mul(usize, size, n) catch return error.TooLarge;
    if (total > budget.*) return error.TooLarge;
    budget.* -= total;
}

fn keyName(comptime T: type, comptime field: []const u8) []const u8 {
    if (@hasDecl(T, "yaml_keys") and @hasField(@TypeOf(T.yaml_keys), field)) return @field(T.yaml_keys, field);
    return field;
}

fn into(comptime T: type, arena: Allocator, v: Value, options: Options, budget: *usize) Error!T {
    if (T == Value) return v;
    switch (@typeInfo(T)) {
        .bool => return switch (v) {
            .bool => |b| b,
            else => error.WrongType,
        },
        .void => return switch (v) {
            .null => {},
            else => error.WrongType,
        },
        .int => return switch (v) {
            .int => |i| std.math.cast(T, i) orelse error.Overflow,
            else => error.WrongType,
        },
        .float => switch (v) {
            .float => |f| {
                const y: T = @floatCast(f);
                if (!std.math.isNan(f) and @as(f64, y) != f) return error.Overflow;
                return y;
            },
            .int => |i| {
                const y: T = @floatFromInt(i);
                // Exact only: 2^53 + 1 does not survive the trip into f64.
                if (@as(f64, y) != @as(f64, @floatFromInt(i)) or std.math.lossyCast(i64, @as(f64, y)) != i) return error.Overflow;
                return y;
            },
            else => return error.WrongType,
        },
        .optional => |info| return switch (v) {
            .null => null,
            else => try into(info.child, arena, v, options, budget),
        },
        .@"enum" => return switch (v) {
            .string => |s| std.meta.stringToEnum(T, s) orelse error.InvalidEnum,
            else => error.WrongType,
        },
        .array => |info| {
            const items = switch (v) {
                .sequence => |s| s,
                else => return error.WrongType,
            };
            if (items.len != info.len) return error.LengthMismatch;
            var out: T = undefined;
            for (&out, items) |*o, it| o.* = try into(info.child, arena, it, options, budget);
            return out;
        },
        .pointer => |info| switch (info.size) {
            .one => {
                try charge(budget, @sizeOf(info.child), 1);
                const p = try arena.create(info.child);
                p.* = try into(info.child, arena, v, options, budget);
                return p;
            },
            .slice => {
                if (info.sentinel_ptr != null) @compileError("yaml.typed: sentinel-terminated slices are not mapped");
                if (info.child == u8) {
                    const s = switch (v) {
                        .string => |s| s,
                        else => return error.WrongType,
                    };
                    if (info.is_const) return s;
                    try charge(budget, 1, s.len);
                    return try arena.dupe(u8, s);
                }
                const items = switch (v) {
                    .sequence => |s| s,
                    else => return error.WrongType,
                };
                try charge(budget, @sizeOf(info.child), items.len);
                const out = try arena.alloc(info.child, items.len);
                for (out, items) |*o, it| o.* = try into(info.child, arena, it, options, budget);
                return out;
            },
            else => @compileError("yaml.typed: only one-item pointers and slices are mapped, not " ++ @typeName(T)),
        },
        .@"struct" => |info| {
            if (info.is_tuple) {
                const items = switch (v) {
                    .sequence => |s| s,
                    else => return error.WrongType,
                };
                if (items.len != info.fields.len) return error.LengthMismatch;
                var out: T = undefined;
                inline for (info.fields, 0..) |f, i| out[i] = try into(f.type, arena, items[i], options, budget);
                return out;
            }
            const pairs = switch (v) {
                .mapping => |m| m,
                .null => &[_]Pair{}, // an empty document / `key:` with nothing is a struct of defaults
                else => return error.WrongType,
            };
            var out: T = undefined;
            var seen: [info.fields.len]bool = @splat(false);
            for (pairs) |p| {
                const k = switch (p.key) {
                    .string => |s| s,
                    else => {
                        if (!options.ignore_unknown_fields) return error.UnknownField;
                        continue;
                    },
                };
                var matched = false;
                inline for (info.fields, 0..) |f, i| {
                    if (!f.is_comptime and !matched and std.mem.eql(u8, k, comptime keyName(T, f.name))) {
                        if (seen[i]) return error.DuplicateField;
                        seen[i] = true;
                        matched = true;
                        @field(out, f.name) = try into(f.type, arena, p.value, options, budget);
                    }
                }
                if (!matched and !options.ignore_unknown_fields) return error.UnknownField;
            }
            inline for (info.fields, 0..) |f, i| {
                if (!f.is_comptime and !seen[i]) {
                    if (f.defaultValue()) |d| {
                        @field(out, f.name) = d;
                    } else if (@typeInfo(f.type) == .optional) {
                        @field(out, f.name) = null;
                    } else return error.MissingField;
                }
            }
            return out;
        },
        .@"union" => |info| {
            if (info.tag_type == null) @compileError("yaml.typed: only tagged unions are mapped");
            switch (v) {
                .string => |s| inline for (info.fields) |f| {
                    if (f.type == void and std.mem.eql(u8, s, f.name)) return @unionInit(T, f.name, {});
                },
                .mapping => |m| if (m.len == 1 and m[0].key == .string) {
                    inline for (info.fields) |f| {
                        if (std.mem.eql(u8, m[0].key.string, f.name))
                            return @unionInit(T, f.name, try into(f.type, arena, m[0].value, options, budget));
                    }
                    return error.InvalidEnum;
                } else return error.WrongType,
                else => return error.WrongType,
            }
            return error.InvalidEnum;
        },
        else => @compileError("yaml.typed: type not mapped: " ++ @typeName(T)),
    }
}

// ── Zig value → Value ──────────────────────────────────────────────────────

/// The `Value` for `x` (allocated in `arena`; may alias `x`'s slices). A
/// struct's `null` optional fields are left out.
pub fn toValue(arena: Allocator, x: anytype) Allocator.Error!Value {
    return from(@TypeOf(x), arena, x);
}

/// `toValue` then the emitter: YAML text in a new `gpa`-owned slice.
pub fn stringify(gpa: Allocator, x: anytype) (Allocator.Error || @import("emit.zig").Error)![]u8 {
    var arena: std.heap.ArenaAllocator = .init(gpa);
    defer arena.deinit();
    const v = try toValue(arena.allocator(), x);
    return @import("emit.zig").stringify(gpa, v);
}

fn from(comptime T: type, arena: Allocator, x: T) Allocator.Error!Value {
    if (T == Value) return x;
    switch (@typeInfo(T)) {
        .bool => return .{ .bool = x },
        .void, .null => return .null,
        .int => return .{ .int = std.math.cast(i64, x) orelse return .{ .string = try std.fmt.allocPrint(arena, "{d}", .{x}) } },
        .comptime_int => return .{ .int = x },
        .float => return .{ .float = @floatCast(x) },
        .comptime_float => return .{ .float = x },
        .optional => |info| return if (x) |c| from(info.child, arena, c) else .null,
        .@"enum" => return .{ .string = @tagName(x) },
        .enum_literal => return .{ .string = @tagName(x) },
        .array => |info| {
            const out = try arena.alloc(Value, info.len);
            for (out, x) |*o, it| o.* = try from(info.child, arena, it);
            return .{ .sequence = out };
        },
        .pointer => |info| switch (info.size) {
            .one => {
                if (@typeInfo(info.child) == .array and @typeInfo(info.child).array.child == u8) {
                    const s: []const u8 = x;
                    return .{ .string = s };
                }
                return from(info.child, arena, x.*);
            },
            .slice => {
                if (info.child == u8) return .{ .string = x };
                const out = try arena.alloc(Value, x.len);
                for (out, x) |*o, it| o.* = try from(info.child, arena, it);
                return .{ .sequence = out };
            },
            else => @compileError("yaml.typed: only one-item pointers and slices are mapped, not " ++ @typeName(T)),
        },
        .@"struct" => |info| {
            if (info.is_tuple) {
                const out = try arena.alloc(Value, info.fields.len);
                inline for (info.fields, 0..) |f, i| out[i] = try from(f.type, arena, x[i]);
                return .{ .sequence = out };
            }
            var n: usize = 0;
            inline for (info.fields) |f| {
                if (!isNull(@field(x, f.name))) n += 1;
            }
            const out = try arena.alloc(Pair, n);
            var i: usize = 0;
            inline for (info.fields) |f| {
                const fv = @field(x, f.name);
                if (!isNull(fv)) {
                    out[i] = .{ .key = .{ .string = comptime keyName(T, f.name) }, .value = try from(f.type, arena, fv) };
                    i += 1;
                }
            }
            return .{ .mapping = out };
        },
        .@"union" => |info| {
            if (info.tag_type == null) @compileError("yaml.typed: only tagged unions are mapped");
            switch (x) {
                inline else => |payload, tag| {
                    if (@TypeOf(payload) == void) return .{ .string = @tagName(tag) };
                    const out = try arena.alloc(Pair, 1);
                    out[0] = .{ .key = .{ .string = @tagName(tag) }, .value = try from(@TypeOf(payload), arena, payload) };
                    return .{ .mapping = out };
                },
            }
        },
        else => @compileError("yaml.typed: type not mapped: " ++ @typeName(T)),
    }
}

fn isNull(x: anytype) bool {
    return switch (@typeInfo(@TypeOf(x))) {
        .optional => x == null,
        .null => true,
        else => false,
    };
}
