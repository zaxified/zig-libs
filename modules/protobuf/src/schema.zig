// SPDX-License-Identifier: MIT

//! Comptime schema derivation — how a plain Zig struct becomes a protobuf
//! message with **no `.proto` file and no code generation**.
//!
//! A message declares `pub const pb_fields`, a struct literal whose field
//! names match the message's own and whose values are `Field` descriptors:
//!
//! ```zig
//! const Person = struct {
//!     name: []const u8 = "",          // implicit presence
//!     id: i32 = 0,
//!     score: ?f64 = null,             // explicit presence ("optional")
//!     tags: []const []const u8 = &.{},// repeated
//!     home: ?Address = null,          // singular submessage
//!     unknown: protobuf.Unknown = .empty,
//!
//!     pub const pb_fields = .{
//!         .name  = .{ .number = 1, .kind = .string },
//!         .id    = .{ .number = 2, .kind = .int32 },
//!         .score = .{ .number = 3, .kind = .double },
//!         .tags  = .{ .number = 4, .kind = .string },
//!         .home  = .{ .number = 5, .kind = .message },
//!     };
//! };
//! ```
//!
//! **The descriptor names only the proto type; the Zig type carries the
//! cardinality.** `T` is implicit presence, `?T` is explicit presence, and
//! `[]const T` is repeated — so one `kind` never has to be spelled three
//! ways, and a mismatch between the two halves is a compile error rather
//! than a wire-format surprise. Everything the codec needs is therefore
//! derivable by walking `@typeInfo`, and every rule below fails at compile
//! time with a message naming the offending field.

const std = @import("std");

/// Protobuf scalar/composite types. Names match the `.proto` language so a
/// struct can be read against a published schema line by line.
pub const Kind = enum {
    // wire type 0 — varint
    int32,
    int64,
    uint32,
    uint64,
    sint32, // zigzag
    sint64, // zigzag
    bool,
    @"enum",
    // wire type 1 — 64-bit
    fixed64,
    sfixed64,
    double,
    // wire type 5 — 32-bit
    fixed32,
    sfixed32,
    float,
    // wire type 2 — length-delimited
    string,
    bytes,
    message,

    pub fn wireType(self: Kind) @import("wire.zig").WireType {
        return switch (self) {
            .int32, .int64, .uint32, .uint64, .sint32, .sint64, .bool, .@"enum" => .varint,
            .fixed64, .sfixed64, .double => .i64,
            .fixed32, .sfixed32, .float => .i32,
            .string, .bytes, .message => .len,
        };
    }

    /// proto3 packs repeated scalars by default; length-delimited element
    /// types are never packed.
    pub fn packable(self: Kind) bool {
        return self.wireType() != .len;
    }
};

/// A field descriptor, as written in `pb_fields`.
pub const Field = struct {
    number: u32,
    kind: Kind,
    /// Override proto3's default packing for a repeated scalar. `null` =
    /// the proto3 default (packed). Set `false` to emit the legacy
    /// one-tag-per-element form; the decoder accepts both regardless.
    packed_encoding: ?bool = null,
};

pub const Cardinality = enum { singular, optional, repeated };

/// A field descriptor after derivation: descriptor + what the Zig type said.
pub const Info = struct {
    name: []const u8,
    number: u32,
    kind: Kind,
    card: Cardinality,
    is_packed: bool,
    /// The element type: `i32` for `[]const i32`, `[]const u8` for a string.
    Elem: type,
    /// The field is `?*const T` — a boxed singular submessage, the shape a
    /// self-recursive message needs.
    boxed: bool,
};

/// Carrier for fields the decoder did not recognise.
///
/// Declare one field of this type in a message struct and every unknown
/// field is captured **verbatim** — tag bytes and payload exactly as they
/// arrived — and re-emitted on encode. Without it, unknown fields are
/// dropped. See SPEC.md for why this is opt-in and why verbatim.
pub const Unknown = struct {
    /// Raw wire bytes, each entry being a complete tag+value. Owned by the
    /// decode arena; a value built by hand may point at static bytes.
    raw: []const u8 = &.{},

    pub const empty: Unknown = .{};

    pub fn isEmpty(self: Unknown) bool {
        return self.raw.len == 0;
    }
};

/// True if `T` looks like a protobuf message (a struct with `pb_fields`).
pub fn isMessage(comptime T: type) bool {
    return @typeInfo(T) == .@"struct" and @hasDecl(T, "pb_fields");
}

fn typeName(comptime T: type) []const u8 {
    return @typeName(T);
}

/// Derive the full field table for message `T`. Comptime-only (it carries
/// `type` values), consumed exclusively by `inline for`.
pub fn infos(comptime T: type) []const Info {
    comptime {
        // Derivation is O(fields^2) in the duplicate-number check and runs
        // once per message type; the default quota is not enough for a
        // message with more than a handful of fields.
        @setEvalBranchQuota(20_000);
        if (@typeInfo(T) != .@"struct")
            @compileError("protobuf: " ++ typeName(T) ++ " is not a struct");
        if (!@hasDecl(T, "pb_fields"))
            @compileError("protobuf: " ++ typeName(T) ++ " has no `pub const pb_fields`");

        const Desc = @TypeOf(T.pb_fields);
        const desc_fields = @typeInfo(Desc).@"struct".fields;
        const struct_fields = @typeInfo(T).@"struct".fields;

        var out: [desc_fields.len]Info = undefined;
        var n: usize = 0;

        for (struct_fields) |sf| {
            if (sf.type == Unknown) {
                // The unknown-field sink: not a schema field.
                if (@hasField(Desc, sf.name))
                    @compileError("protobuf: " ++ typeName(T) ++ "." ++ sf.name ++
                        " is the Unknown sink and must not appear in pb_fields");
                continue;
            }
            if (!@hasField(Desc, sf.name))
                @compileError("protobuf: " ++ typeName(T) ++ "." ++ sf.name ++
                    " has no pb_fields entry (every field must be described, or be a protobuf.Unknown sink)");
            if (sf.default_value_ptr == null)
                @compileError("protobuf: " ++ typeName(T) ++ "." ++ sf.name ++
                    " needs a default value — the decoder starts from `T{}` so an absent field keeps proto3's default");

            const desc: Field = @field(T.pb_fields, sf.name);
            validateNumber(T, sf.name, desc.number);
            const shape = classify(T, sf.name, sf.type, desc.kind);

            out[n] = .{
                .name = sf.name,
                .number = desc.number,
                .kind = desc.kind,
                .card = shape.card,
                .is_packed = shape.card == .repeated and desc.kind.packable() and
                    (desc.packed_encoding orelse true),
                .Elem = shape.Elem,
                .boxed = shape.boxed,
            };
            if (desc.packed_encoding != null and !desc.kind.packable())
                @compileError("protobuf: " ++ typeName(T) ++ "." ++ sf.name ++
                    " is length-delimited and can never be packed");
            n += 1;
        }

        if (n != desc_fields.len) {
            // Some pb_fields entry names a field that does not exist.
            for (desc_fields) |df| {
                if (!@hasField(T, df.name))
                    @compileError("protobuf: pb_fields entry ." ++ df.name ++
                        " does not name a field of " ++ typeName(T));
            }
            @compileError("protobuf: pb_fields/field count mismatch on " ++ typeName(T));
        }

        // Duplicate field numbers make one of the two silently unreachable.
        for (out[0..n], 0..) |a, i| for (out[i + 1 .. n]) |b| {
            if (a.number == b.number)
                @compileError("protobuf: " ++ typeName(T) ++ " reuses field number " ++
                    numStr(a.number) ++ " for ." ++ a.name ++ " and ." ++ b.name);
        };

        const frozen = out[0..n].*;
        return &frozen;
    }
}

fn numStr(comptime n: u32) []const u8 {
    return std.fmt.comptimePrint("{d}", .{n});
}

fn validateNumber(comptime T: type, comptime name: []const u8, comptime number: u32) void {
    if (number == 0)
        @compileError("protobuf: " ++ typeName(T) ++ "." ++ name ++ " field number 0 is reserved");
    if (number > 536_870_911) // 2^29 - 1
        @compileError("protobuf: " ++ typeName(T) ++ "." ++ name ++ " field number exceeds 2^29-1");
    if (number >= 19_000 and number <= 19_999)
        @compileError("protobuf: " ++ typeName(T) ++ "." ++ name ++
            " field number is in the implementation-reserved range 19000-19999");
}

const Shape = struct { card: Cardinality, Elem: type, boxed: bool };

fn classify(
    comptime T: type,
    comptime name: []const u8,
    comptime FieldType: type,
    comptime kind: Kind,
) Shape {
    const where = "protobuf: " ++ typeName(T) ++ "." ++ name;

    // ?X — explicit presence, or a boxed submessage.
    if (@typeInfo(FieldType) == .optional) {
        const Child = @typeInfo(FieldType).optional.child;
        if (kind == .message) {
            const ci = @typeInfo(Child);
            if (ci == .pointer and ci.pointer.size == .one) {
                checkElem(where, ci.pointer.child, kind);
                return .{ .card = .optional, .Elem = ci.pointer.child, .boxed = true };
            }
        }
        if (isSlice(Child) and !isByteSlice(Child))
            @compileError(where ++ ": optional repeated is not a protobuf shape — use []const T alone");
        checkElem(where, Child, kind);
        return .{ .card = .optional, .Elem = Child, .boxed = false };
    }

    if (kind == .string or kind == .bytes) {
        if (isByteSlice(FieldType))
            return .{ .card = .singular, .Elem = []const u8, .boxed = false };
        if (isSlice(FieldType) and isByteSlice(@typeInfo(FieldType).pointer.child))
            return .{ .card = .repeated, .Elem = []const u8, .boxed = false };
        @compileError(where ++ ": kind ." ++ @tagName(kind) ++
            " wants []const u8 (singular) or []const []const u8 (repeated), got " ++ typeName(FieldType));
    }

    if (isSlice(FieldType)) {
        const Child = @typeInfo(FieldType).pointer.child;
        checkElem(where, Child, kind);
        return .{ .card = .repeated, .Elem = Child, .boxed = false };
    }

    if (kind == .message)
        @compileError(where ++ ": a singular message has explicit presence in proto3 — declare it ?" ++
            typeName(FieldType) ++ " (or ?*const " ++ typeName(FieldType) ++ " to recurse)");

    checkElem(where, FieldType, kind);
    return .{ .card = .singular, .Elem = FieldType, .boxed = false };
}

fn isSlice(comptime T: type) bool {
    const ti = @typeInfo(T);
    return ti == .pointer and ti.pointer.size == .slice;
}

fn isByteSlice(comptime T: type) bool {
    return isSlice(T) and @typeInfo(T).pointer.child == u8;
}

/// The proto type fixes the Zig element type; a mismatch is a compile error,
/// which is the whole reason the descriptor does not also restate the type.
fn checkElem(comptime where: []const u8, comptime E: type, comptime kind: Kind) void {
    const want: ?type = switch (kind) {
        .int32, .sint32, .sfixed32 => i32,
        .int64, .sint64, .sfixed64 => i64,
        .uint32, .fixed32 => u32,
        .uint64, .fixed64 => u64,
        .bool => bool,
        .float => f32,
        .double => f64,
        .string, .bytes => []const u8,
        .@"enum", .message => null,
    };
    if (want) |W| {
        if (E != W)
            @compileError(where ++ ": kind ." ++ @tagName(kind) ++ " wants " ++ typeName(W) ++
                ", got " ++ typeName(E));
        return;
    }
    switch (kind) {
        .@"enum" => {
            if (@typeInfo(E) != .@"enum")
                @compileError(where ++ ": kind .enum wants an enum type, got " ++ typeName(E));
            // A protobuf enum is exactly an int32 on the wire, including its
            // negative range, so the Zig tag type must say so rather than
            // leaving the width to Zig's default (u1 for a two-value enum).
            // Non-exhaustive `enum(i32) { …, _ }` is the recommended form:
            // proto3 enums are open, and only a non-exhaustive enum can hold
            // a value added by a newer peer.
            if (@typeInfo(E).@"enum".tag_type != i32)
                @compileError(where ++ ": a protobuf enum is an int32 — declare " ++
                    typeName(E) ++ " as `enum(i32) { …, _ }`");
        },
        .message => {
            if (!isMessage(E))
                @compileError(where ++ ": kind .message wants a struct with pb_fields, got " ++ typeName(E));
        },
        else => unreachable,
    }
}

// ── tests ───────────────────────────────────────────────────────────────────

const testing = std.testing;

const Sample = struct {
    a: i32 = 0,
    b: ?u64 = null,
    c: []const u8 = "",
    d: []const []const u8 = &.{},
    e: []const i32 = &.{},
    f: []const i32 = &.{},
    unknown: Unknown = .empty,

    pub const pb_fields = .{
        .a = Field{ .number = 1, .kind = .int32 },
        .b = Field{ .number = 2, .kind = .uint64 },
        .c = Field{ .number = 3, .kind = .string },
        .d = Field{ .number = 4, .kind = .string },
        .e = Field{ .number = 5, .kind = .int32 },
        .f = Field{ .number = 6, .kind = .int32, .packed_encoding = false },
    };
};

test "derivation: cardinality comes from the Zig type, not the descriptor" {
    const t = comptime infos(Sample);
    try testing.expectEqual(@as(usize, 6), t.len);

    try testing.expectEqual(Cardinality.singular, t[0].card);
    try testing.expectEqual(Cardinality.optional, t[1].card);
    try testing.expectEqual(Cardinality.singular, t[2].card); // []const u8 + .string
    try testing.expectEqual(Cardinality.repeated, t[3].card); // []const []const u8
    try testing.expectEqual(Cardinality.repeated, t[4].card);

    // The Unknown sink is not a schema field.
    inline for (t) |i| try testing.expect(!std.mem.eql(u8, i.name, "unknown"));
}

test "derivation: proto3 packs repeated scalars by default, never length-delimited" {
    const t = comptime infos(Sample);
    try testing.expect(t[4].is_packed); // repeated int32 -> packed
    try testing.expect(!t[5].is_packed); // explicit opt-out
    try testing.expect(!t[3].is_packed); // repeated string is never packed
    try testing.expect(!t[0].is_packed); // not repeated at all
}

test "kind: wire type mapping matches the encoding spec" {
    try testing.expectEqual(@import("wire.zig").WireType.varint, Kind.sint64.wireType());
    try testing.expectEqual(@import("wire.zig").WireType.varint, Kind.bool.wireType());
    try testing.expectEqual(@import("wire.zig").WireType.i64, Kind.double.wireType());
    try testing.expectEqual(@import("wire.zig").WireType.i32, Kind.float.wireType());
    try testing.expectEqual(@import("wire.zig").WireType.i32, Kind.sfixed32.wireType());
    try testing.expectEqual(@import("wire.zig").WireType.len, Kind.bytes.wireType());
    try testing.expect(Kind.@"enum".packable());
    try testing.expect(!Kind.message.packable());
}
