// SPDX-License-Identifier: MIT
//! Comptime mapping between Zig types and CBOR — the struct marshalling a
//! user of fxamacker/cbor, ciborium or zbor expects, over this module's
//! hardened decoder (the bytes are decoded to a `Value` first, with every
//! `DecodeOptions` limit, then mapped).
//!
//! | Zig type                    | CBOR                                                   |
//! |-----------------------------|--------------------------------------------------------|
//! | `bool`                      | `true` / `false`                                       |
//! | integers (≤ 128 bits)       | major type 0/1; beyond 64 bits a bignum (tag 2/3, preferred serialization on encode, leading zeros tolerated on decode); range-checked (`error.Overflow`) |
//! | `f16` / `f32` / `f64`       | any float width; decode refuses a value the target cannot hold exactly (`error.Overflow`) |
//! | `[]const u8`                | text string (UTF-8) — or a byte string, see `bytes` below |
//! | `[N]u8`                     | byte string of exactly N bytes (`error.LengthMismatch`) |
//! | `[]const T`, `[N]T`         | array (`[N]T`: exactly N items)                        |
//! | tuple                       | array of exactly that many items                       |
//! | `struct`                    | map, keyed by field name or by `cbor_options.keys`     |
//! | `?T`                        | `null`/`undefined` ↔ `null`; a `null` struct field is omitted on encode, absent on decode |
//! | `enum`                      | its integer value; decode also takes the tag name as text |
//! | `union(enum)`               | a one-entry map `{field-key: payload}` (`void` payload ↔ `null`) |
//! | `*const T`                  | the `T` it points to                                    |
//! | `cbor.Value`                | the item as is                                          |
//! | a type with `cbor_tag`, `Tagged(N, T)` | the item under tag N (`error.WrongTag` when absent or another) |
//! | `void`                      | `null`                                                  |
//!
//! A struct (or tagged union) may declare how it maps:
//!
//!     const MakeCredential = struct {
//!         client_data_hash: []const u8,
//!         rp: Rp,
//!         options: ?Options = null,
//!         pub const cbor_options = .{
//!             .keys = .{ .client_data_hash = 1, .rp = 2, .options = 7 }, // or a text rename
//!             .bytes = .{.client_data_hash}, // []const u8 fields carried as byte strings
//!         };
//!     };
//!
//! Decode rules for a struct: a missing field takes its default value, or
//! `null` if it is optional, else `error.MissingField`; a key that names a
//! field twice is `error.DuplicateField` (whatever `reject_duplicate_keys`
//! says); an unknown key is skipped unless `Options.ignore_unknown_fields` is
//! off (`error.UnknownField`).
//!
//! **Memory.** `decode` returns a `Parsed(T)` that owns an arena with both
//! the intermediate `Value` tree and everything `T` points into; `deinit`
//! frees it. `decodeLeaky`/`fromValue` put everything into the allocator
//! you pass, and the result may alias the `Value` it came from — use an
//! arena. No pre-allocation follows a declared length: a slice is allocated
//! for the items the input actually contained.

const std = @import("std");
const root = @import("root.zig");

/// Zig 0.17 `@typeInfo` is struct-of-arrays (no `.fields`); this rebuilds the per-field
/// records (`name`, `type`, `is_comptime`, `defaultValue()`) that the code below iterates.
const FieldRec = struct {
    name: [:0]const u8,
    type: type,
    is_comptime: bool,
    default_value_ptr: ?*const anyopaque,

    fn defaultValue(comptime f: FieldRec) ?f.type {
        const dp: *const f.type = @ptrCast(@alignCast(f.default_value_ptr orelse return null));
        return dp.*;
    }
};

fn fieldRecs(comptime info: anytype) [info.field_names.len]FieldRec {
    var out: [info.field_names.len]FieldRec = undefined;
    for (info.field_names, info.field_types, 0..) |n, t, i| {
        const a = info.field_attrs[i];
        out[i] = .{
            .name = n,
            .type = t,
            .is_comptime = if (@hasField(@TypeOf(a), "comptime")) a.@"comptime" else false,
            .default_value_ptr = if (@hasField(@TypeOf(a), "default_value_ptr")) a.default_value_ptr else null,
        };
    }
    return out;
}
const Value = root.Value;
const MapEntry = root.MapEntry;
const Allocator = std.mem.Allocator;

pub const Error = root.DecodeError || error{
    /// The CBOR item is of a different kind than the Zig type asks for.
    WrongType,
    /// A number does not fit the target type (an integer out of range, a
    /// float the narrower target cannot hold exactly).
    Overflow,
    /// A required struct field (no default, not optional) is absent.
    MissingField,
    /// A map key matched no field and `ignore_unknown_fields` is off.
    UnknownField,
    /// Two map keys named the same struct field.
    DuplicateField,
    /// A fixed-size array or byte string had another length.
    LengthMismatch,
    /// An integer or name that is no member of the enum, or a union map
    /// whose key names no variant.
    InvalidEnum,
    /// Mapping would allocate more than `Options.max_alloc_bytes`.
    TooLarge,
    /// A type that declares `cbor_tag` met an item without that tag, or with
    /// another tag number.
    WrongTag,
};

pub const Options = struct {
    decode: root.DecodeOptions = .{},
    ignore_unknown_fields: bool = true,
    /// Cap on what the mapping itself allocates (slices, pointed-to items,
    /// copied strings) — not the `Value` tree, which `decode` bounds by the
    /// input. A one-byte CBOR item can become a large `T` (`a0` is a whole
    /// struct of defaults), so `[]const T` from an array of N such items asks
    /// for N × @sizeOf(T): without the cap, 2 MB of `a0` into a 64 KiB struct
    /// would be a 128 GiB request. Past the cap: `error.TooLarge`.
    max_alloc_bytes: usize = 64 << 20,
};

/// `T` carried under tag `number` wherever it appears (a struct field, a
/// slice item, the top-level item): `Tagged(1, i64)` is an epoch time (RFC
/// 8949 §3.4.2), `Tagged(0, []const u8)` a date/time string. Decoding without
/// that tag, or with another, is `error.WrongTag`. The wrapped value is
/// `.value`. A struct, enum or tagged union of your own does the same with
/// `pub const cbor_tag: u64 = N;`.
pub fn Tagged(comptime number: u64, comptime T: type) type {
    return struct {
        value: T,

        pub const cbor_tag = number;
        pub const cbor_transparent = true;
    };
}

/// A decoded `T` and the arena that holds it.
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

/// Decode `bytes` (exactly one item) into a `T`, owning its memory.
pub fn decode(comptime T: type, gpa: Allocator, bytes: []const u8, options: Options) Error!Parsed(T) {
    const arena = try gpa.create(std.heap.ArenaAllocator);
    errdefer gpa.destroy(arena);
    arena.* = .init(gpa);
    errdefer arena.deinit();
    const v = try decodeLeaky(T, arena.allocator(), bytes, options);
    return .{ .arena = arena, .value = v };
}

/// `decode` into a caller-managed allocator (an arena: nothing is freed
/// individually).
pub fn decodeLeaky(comptime T: type, arena: Allocator, bytes: []const u8, options: Options) Error!T {
    const v = try root.decode(arena, bytes, options.decode);
    return fromValue(T, arena, v, options);
}

/// Map an already decoded `Value` onto `T`. The result may alias `v`.
pub fn fromValue(comptime T: type, arena: Allocator, v: Value, options: Options) Error!T {
    var budget = options.max_alloc_bytes;
    return valueInto(T, false, arena, v, options, &budget);
}

fn charge(budget: *usize, size: usize, n: usize) Error!void {
    const total = std.math.mul(usize, size, n) catch return error.TooLarge;
    if (total > budget.*) return error.TooLarge;
    budget.* -= total;
}

/// The `Value` for `x` (allocated in `arena`; may alias `x`'s slices).
pub fn toValue(arena: Allocator, x: anytype) Allocator.Error!Value {
    return valueFrom(@TypeOf(x), false, arena, x);
}

/// Encode `x` to `gpa`-owned bytes (`root.encode` options apply:
/// `.canonical = true` for the deterministic form).
pub fn encode(gpa: Allocator, x: anytype, options: root.EncodeOptions) root.EncodeError![]u8 {
    var arena: std.heap.ArenaAllocator = .init(gpa);
    defer arena.deinit();
    const v = try toValue(arena.allocator(), x);
    return root.encode(gpa, v, options);
}

// ── struct metadata ────────────────────────────────────────────────────────

const Key = union(enum) { int: i64, text: []const u8 };

fn fieldKey(comptime T: type, comptime name: []const u8) Key {
    if (@hasDecl(T, "cbor_options") and @hasField(@TypeOf(T.cbor_options), "keys") and
        @hasField(@TypeOf(T.cbor_options.keys), name))
    {
        const k = @field(T.cbor_options.keys, name);
        return switch (@typeInfo(@TypeOf(k))) {
            .comptime_int, .int => .{ .int = k },
            .pointer => .{ .text = k },
            else => @compileError("cbor_options.keys." ++ name ++ ": an integer or a string"),
        };
    }
    return .{ .text = name };
}

fn fieldIsBytes(comptime T: type, comptime name: []const u8) bool {
    if (!(@hasDecl(T, "cbor_options") and @hasField(@TypeOf(T.cbor_options), "bytes"))) return false;
    inline for (T.cbor_options.bytes) |f| {
        if (comptime std.mem.eql(u8, @tagName(f), name)) return true;
    }
    return false;
}

fn keyMatches(key: Value, comptime k: Key) bool {
    return switch (k) {
        .int => |i| if (key.toI64()) |ki| ki == i else false,
        .text => |t| key == .text and std.mem.eql(u8, key.text, t),
    };
}

fn keyValue(comptime k: Key) Value {
    return switch (k) {
        .int => |i| Value.fromI64(i),
        .text => |t| .{ .text = t },
    };
}

// ── decode ─────────────────────────────────────────────────────────────────

/// The tag number a type declares with `pub const cbor_tag`, if any.
fn tagOf(comptime T: type) ?u64 {
    return switch (@typeInfo(T)) {
        .@"struct", .@"enum", .@"union" => if (@hasDecl(T, "cbor_tag")) @as(u64, T.cbor_tag) else null,
        else => null,
    };
}

fn valueInto(comptime T: type, comptime as_bytes: bool, arena: Allocator, v: Value, options: Options, budget: *usize) Error!T {
    if (comptime tagOf(T)) |number| {
        const t = switch (v) {
            .tag => |t| t,
            else => return error.WrongTag,
        };
        if (t.number != number) return error.WrongTag;
        return valueIntoRaw(T, as_bytes, arena, t.value.*, options, budget);
    }
    return valueIntoRaw(T, as_bytes, arena, v, options, budget);
}

/// An integer item for `T`: major type 0/1, or a bignum (tag 2/3, RFC 8949 §3.4.3; leading zero bytes tolerated).
fn intInto(comptime T: type, v: Value) Error!T {
    switch (v) {
        .uint => |u| return std.math.cast(T, u) orelse error.Overflow,
        .negint => |n| return std.math.cast(T, -1 - @as(i256, n)) orelse error.Overflow,
        .tag => |t| {
            if (t.number != 2 and t.number != 3) return error.WrongType;
            const b = switch (t.value.*) {
                .bytes => |b| b,
                else => return error.WrongType,
            };
            var i: usize = 0;
            while (i < b.len and b[i] == 0) i += 1;
            if (b.len - i > 16) return error.Overflow;
            var n: u128 = 0;
            for (b[i..]) |x| n = (n << 8) | x;
            const val: i256 = if (t.number == 2) @as(i256, n) else -1 - @as(i256, n);
            return std.math.cast(T, val) orelse error.Overflow;
        },
        else => return error.WrongType,
    }
}

fn valueIntoRaw(comptime T: type, comptime as_bytes: bool, arena: Allocator, v: Value, options: Options, budget: *usize) Error!T {
    if (T == Value) return v;
    switch (@typeInfo(T)) {
        .bool => return switch (v) {
            .bool => |b| b,
            else => error.WrongType,
        },
        .void => return switch (v) {
            .null_value, .undefined_value => {},
            else => error.WrongType,
        },
        .int => |info| {
            if (info.bits > 128) @compileError("cbor.typed: integers wider than 128 bits are not mapped");
            return intInto(T, v);
        },
        .float => {
            const x: f64 = switch (v) {
                .f16 => |f| f,
                .f32 => |f| f,
                .f64 => |f| f,
                else => return error.WrongType,
            };
            const y: T = @floatCast(x);
            if (std.math.isNan(x)) return y;
            if (@as(u64, @bitCast(@as(f64, y))) != @as(u64, @bitCast(x))) return error.Overflow;
            return y;
        },
        .optional => |info| return switch (v) {
            .null_value, .undefined_value => null,
            else => try valueInto(info.child, as_bytes, arena, v, options, budget),
        },
        .@"enum" => |info| switch (v) {
            .uint, .negint => {
                const i = try valueInto(info.tag_type, false, arena, v, options, budget);
                return std.enums.fromInt(T, i) orelse error.InvalidEnum;
            },
            .text => |t| return std.meta.stringToEnum(T, t) orelse error.InvalidEnum,
            else => return error.WrongType,
        },
        .array => |info| {
            var out: T = undefined;
            if (info.child == u8) {
                const b = switch (v) {
                    .bytes => |b| b,
                    else => return error.WrongType,
                };
                if (b.len != info.len) return error.LengthMismatch;
                @memcpy(&out, b);
                return out;
            }
            const items = switch (v) {
                .array => |a| a,
                else => return error.WrongType,
            };
            if (items.len != info.len) return error.LengthMismatch;
            for (&out, items) |*o, it| o.* = try valueInto(info.child, false, arena, it, options, budget);
            return out;
        },
        .pointer => |info| switch (info.size) {
            .one => {
                try charge(budget, @sizeOf(info.child), 1);
                const p = try arena.create(info.child);
                p.* = try valueInto(info.child, as_bytes, arena, v, options, budget);
                return p;
            },
            .slice => {
                if (info.sentinel_ptr != null) @compileError("cbor.typed: sentinel-terminated slices are not mapped");
                if (info.child == u8) {
                    const s = switch (v) {
                        .bytes => |b| if (as_bytes) b else return error.WrongType,
                        .text => |t| if (!as_bytes) t else return error.WrongType,
                        else => return error.WrongType,
                    };
                    if (info.attrs.@"const") return s;
                    try charge(budget, 1, s.len);
                    return try arena.dupe(u8, s);
                }
                const items = switch (v) {
                    .array => |a| a,
                    else => return error.WrongType,
                };
                try charge(budget, @sizeOf(info.child), items.len);
                const out = try arena.alloc(info.child, items.len);
                for (out, items) |*o, it| o.* = try valueInto(info.child, as_bytes, arena, it, options, budget);
                return out;
            },
            else => @compileError("cbor.typed: only one-item pointers and slices are mapped, not " ++ @typeName(T)),
        },
        .@"struct" => |info| {
            if (@hasDecl(T, "cbor_transparent")) {
                var out: T = undefined;
                out.value = try valueInto(@FieldType(T, "value"), false, arena, v, options, budget);
                return out;
            }
            if (info.is_tuple) {
                const items = switch (v) {
                    .array => |a| a,
                    else => return error.WrongType,
                };
                if (items.len != info.field_names.len) return error.LengthMismatch;
                var out: T = undefined;
                inline for (fieldRecs(info), 0..) |f, i| out[i] = try valueInto(f.type, false, arena, items[i], options, budget);
                return out;
            }
            const entries = switch (v) {
                .map => |m| m,
                else => return error.WrongType,
            };
            var out: T = undefined;
            var seen: [info.field_names.len]bool = @splat(false);
            for (entries) |e| {
                var matched = false;
                inline for (fieldRecs(info), 0..) |f, i| {
                    if (!f.is_comptime and !matched and keyMatches(e.key, comptime fieldKey(T, f.name))) {
                        if (seen[i]) return error.DuplicateField;
                        seen[i] = true;
                        matched = true;
                        @field(out, f.name) = try valueInto(f.type, comptime fieldIsBytes(T, f.name), arena, e.value, options, budget);
                    }
                }
                if (!matched and !options.ignore_unknown_fields) return error.UnknownField;
            }
            inline for (fieldRecs(info), 0..) |f, i| {
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
            if (info.tag_type == null) @compileError("cbor.typed: only tagged unions are mapped");
            const entries = switch (v) {
                .map => |m| m,
                else => return error.WrongType,
            };
            if (entries.len != 1) return error.WrongType;
            const e = entries[0];
            inline for (fieldRecs(info)) |f| {
                if (keyMatches(e.key, comptime fieldKey(T, f.name))) {
                    const payload = try valueInto(f.type, comptime fieldIsBytes(T, f.name), arena, e.value, options, budget);
                    return @unionInit(T, f.name, payload);
                }
            }
            return error.InvalidEnum;
        },
        else => @compileError("cbor.typed: type not mapped: " ++ @typeName(T)),
    }
}

// ── encode ─────────────────────────────────────────────────────────────────

fn intValue(x: anytype) Value {
    if (x < 0) return .{ .negint = @intCast(-1 - @as(i128, x)) };
    return .{ .uint = @intCast(x) };
}

/// An integer of up to 128 bits: major type 0/1 when it fits 64 bits, else a bignum (tag 2/3, preferred serialization).
fn bigIntValue(arena: Allocator, x: anytype) Allocator.Error!Value {
    const v: i256 = x;
    if (v >= 0 and v <= std.math.maxInt(u64)) return .{ .uint = @intCast(v) };
    if (v < 0 and -1 - v <= std.math.maxInt(u64)) return .{ .negint = @intCast(-1 - v) };
    const mag: u128 = @intCast(if (v < 0) -1 - v else v);
    const len = (128 - @clz(mag) + 7) / 8;
    const bytes = try arena.alloc(u8, len);
    var m = mag;
    var i = len;
    while (i > 0) {
        i -= 1;
        bytes[i] = @truncate(m);
        m >>= 8;
    }
    const inner = try arena.create(Value);
    inner.* = .{ .bytes = bytes };
    return .{ .tag = .{ .number = if (v < 0) 3 else 2, .value = inner } };
}

fn valueFrom(comptime T: type, comptime as_bytes: bool, arena: Allocator, x: T) Allocator.Error!Value {
    const inner = try valueFromRaw(T, as_bytes, arena, x);
    if (comptime tagOf(T)) |number| {
        const p = try arena.create(Value);
        p.* = inner;
        return .{ .tag = .{ .number = number, .value = p } };
    }
    return inner;
}

fn valueFromRaw(comptime T: type, comptime as_bytes: bool, arena: Allocator, x: T) Allocator.Error!Value {
    if (T == Value) return x;
    switch (@typeInfo(T)) {
        .bool => return .{ .bool = x },
        .void, .null => return .null_value,
        .int => |info| {
            if (info.bits > 128) @compileError("cbor.typed: integers wider than 128 bits are not mapped");
            if (info.bits > 64) return bigIntValue(arena, x);
            return intValue(x);
        },
        .comptime_int => return comptime intValue(@as(i65, x)),
        .float => |info| return switch (info.bits) {
            16 => .{ .f16 = x },
            32 => .{ .f32 = x },
            64 => .{ .f64 = x },
            else => @compileError("cbor.typed: only f16/f32/f64 are mapped"),
        },
        .comptime_float => return .{ .f64 = x },
        .optional => |info| return if (x) |c| valueFrom(info.child, as_bytes, arena, c) else .null_value,
        .@"enum" => return intValue(@backingInt(x)),
        .enum_literal => return .{ .text = @tagName(x) },
        .array => |info| {
            if (info.child == u8) return .{ .bytes = try arena.dupe(u8, &x) };
            const out = try arena.alloc(Value, info.len);
            for (out, x) |*o, it| o.* = try valueFrom(info.child, false, arena, it);
            return .{ .array = out };
        },
        .pointer => |info| switch (info.size) {
            .one => {
                // A string literal (`*const [N:0]u8`) is text, like `[]const u8`.
                if (@typeInfo(info.child) == .array and @typeInfo(info.child).array.child == u8) {
                    const s: []const u8 = x;
                    return if (as_bytes) .{ .bytes = s } else .{ .text = s };
                }
                return valueFrom(info.child, as_bytes, arena, x.*);
            },
            .slice => {
                if (info.child == u8) return if (as_bytes) .{ .bytes = x } else .{ .text = x };
                const out = try arena.alloc(Value, x.len);
                for (out, x) |*o, it| o.* = try valueFrom(info.child, as_bytes, arena, it);
                return .{ .array = out };
            },
            else => @compileError("cbor.typed: only one-item pointers and slices are mapped, not " ++ @typeName(T)),
        },
        .@"struct" => |info| {
            if (@hasDecl(T, "cbor_transparent")) return valueFrom(@FieldType(T, "value"), false, arena, x.value);
            if (info.is_tuple) {
                const out = try arena.alloc(Value, info.field_names.len);
                inline for (fieldRecs(info), 0..) |f, i| out[i] = try valueFrom(f.type, false, arena, x[i]);
                return .{ .array = out };
            }
            var n: usize = 0;
            inline for (fieldRecs(info)) |f| {
                if (!isNull(@field(x, f.name))) n += 1;
            }
            const out = try arena.alloc(MapEntry, n);
            var i: usize = 0;
            inline for (fieldRecs(info)) |f| {
                const fv = @field(x, f.name);
                if (!isNull(fv)) {
                    out[i] = .{
                        .key = comptime keyValue(fieldKey(T, f.name)),
                        .value = try valueFrom(f.type, comptime fieldIsBytes(T, f.name), arena, fv),
                    };
                    i += 1;
                }
            }
            return .{ .map = out };
        },
        .@"union" => |info| {
            if (info.tag_type == null) @compileError("cbor.typed: only tagged unions are mapped");
            const out = try arena.alloc(MapEntry, 1);
            switch (x) {
                inline else => |payload, tag| {
                    const name = @tagName(tag);
                    out[0] = .{
                        .key = comptime keyValue(fieldKey(T, name)),
                        .value = try valueFrom(@TypeOf(payload), comptime fieldIsBytes(T, name), arena, payload),
                    };
                },
            }
            return .{ .map = out };
        },
        else => @compileError("cbor.typed: type not mapped: " ++ @typeName(T)),
    }
}

fn isNull(x: anytype) bool {
    return switch (@typeInfo(@TypeOf(x))) {
        .optional => x == null,
        .null => true,
        else => false,
    };
}
