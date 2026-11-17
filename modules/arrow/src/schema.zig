// SPDX-License-Identifier: MIT

//! Arrow schema metadata: the `Schema`, `Field`, type and `DictionaryEncoding`
//! tables of `Schema.fbs`, and the `Message` envelope of `Message.fbs`, read
//! from and written to FlatBuffers (`fb.zig`). Field ids and enum values follow
//! the Arrow columnar format specification (format version 1.x, metadata
//! version V5).

const std = @import("std");
const fb = @import("fb.zig");

pub const Error = fb.Error || error{ OutOfMemory, Unsupported };

/// Nesting deeper than this is refused (`error.Malformed`): a hostile schema
/// cannot recurse the decoder off the stack.
pub const max_depth = 64;

pub const MetadataVersion = enum(i16) { v1 = 0, v2 = 1, v3 = 2, v4 = 3, v5 = 4, _ };
pub const TimeUnit = enum(i16) { second = 0, millisecond = 1, microsecond = 2, nanosecond = 3 };
pub const DateUnit = enum(i16) { day = 0, millisecond = 1 };
pub const Precision = enum(i16) { half = 0, single = 1, double = 2 };

pub const IntType = struct { bits: u8, signed: bool };

/// The logical types this module reads and writes (`run_end_encoded` is read only).
/// `unsupported` keeps the union id of a type it does not (Interval, Union, Map,
/// the view types), so a reader can name it.
pub const Type = union(enum) {
    null,
    int: IntType,
    float: Precision,
    binary,
    utf8,
    bool,
    decimal: struct { precision: i32, scale: i32, bits: i32 = 128 },
    date: DateUnit,
    time: struct { unit: TimeUnit, bits: i32 },
    timestamp: struct { unit: TimeUnit, tz: ?[]const u8 = null },
    list,
    @"struct",
    fixed_size_binary: i32,
    fixed_size_list: i32,
    duration: TimeUnit,
    large_binary,
    large_utf8,
    large_list,
    /// Two children: `run_ends` (Int16/32/64) and `values`.
    run_end_encoded,
    unsupported: u8,
};

pub const KeyValue = struct { key: []const u8, value: []const u8 };

pub const Dictionary = struct {
    id: i64,
    /// The index type; Arrow's default when absent is a signed 32-bit integer.
    index: IntType = .{ .bits = 32, .signed = true },
    ordered: bool = false,
};

pub const Field = struct {
    name: []const u8 = "",
    nullable: bool = true,
    type: Type,
    /// Set when the column is dictionary-encoded; `type` is then the type of the dictionary's values.
    dictionary: ?Dictionary = null,
    children: []const Field = &.{},
    metadata: []const KeyValue = &.{},
};

pub const Schema = struct {
    fields: []const Field,
    metadata: []const KeyValue = &.{},
};

// Union ids of `Type` in Schema.fbs.
const tid = struct {
    const null_ = 1;
    const int = 2;
    const float = 3;
    const binary = 4;
    const utf8 = 5;
    const bool_ = 6;
    const decimal = 7;
    const date = 8;
    const time = 9;
    const timestamp = 10;
    const list = 12;
    const struct_ = 13;
    const fixed_size_binary = 15;
    const fixed_size_list = 16;
    const duration = 18;
    const large_binary = 19;
    const large_utf8 = 20;
    const large_list = 21;
    const run_end_encoded = 22;
};

// ── decoding ────────────────────────────────────────────────────────────────

/// What one decoded `Field` or `KeyValue` costs the decode budget; a name or zone
/// string costs one unit per byte on top (a reader copies those).
const unit_per_table = 16;

/// The decode budget of a schema in a FlatBuffer of `len` bytes. FlatBuffers offsets
/// may point at the same table any number of times, so a schema of a few KB can name
/// 2^64 fields through shared children; the budget bounds the TOTAL work, not only
/// the depth. Every honest `Field` takes more than 8 unique bytes (its vector slot,
/// its table, its type id) plus its name's bytes, so an honest schema spends at most
/// about `len` units; twice that leaves room for a writer that shares strings.
fn budgetFor(len: usize) usize {
    return 2 * len + 64;
}

const Decoder = struct {
    arena: std.mem.Allocator,
    left: usize,

    fn charge(d: *Decoder, units: usize) Error!void {
        if (units > d.left) return error.Malformed; // more work than the buffer can honestly hold
        d.left -= units;
    }

    fn tables(d: *Decoder, n: usize) Error!void {
        return d.charge(std.math.mul(usize, n, unit_per_table) catch return error.Malformed);
    }
};

/// Decodes a `Schema` table. Strings point into `buf`; slices are allocated
/// from `arena` (free them all with the arena). The total number of fields and
/// metadata entries decoded, and the bytes of their names, are bounded by the
/// FlatBuffer's length (`error.Malformed` past it): a schema whose tables share
/// children cannot make the decoder do more work than its bytes could describe.
pub fn decodeSchema(arena: std.mem.Allocator, t: fb.Table) Error!Schema {
    const endianness = try t.scalar(i16, 0, 0);
    if (endianness != 0) return error.Unsupported; // big-endian data
    var d: Decoder = .{ .arena = arena, .left = budgetFor(t.buf.len) };
    return .{
        .fields = try decodeFields(&d, try t.vector(1), 0),
        .metadata = try decodeMetadata(&d, try t.vector(2)),
    };
}

fn decodeFields(d: *Decoder, v: ?fb.Vector, depth: usize) Error![]const Field {
    const vec = v orelse return &.{};
    if (depth >= max_depth) return error.Malformed;
    try d.tables(vec.len);
    const out = try d.arena.alloc(Field, vec.len);
    for (out, 0..) |*f, i| f.* = try decodeField(d, try vec.tableAt(i), depth);
    return out;
}

fn decodeMetadata(d: *Decoder, v: ?fb.Vector) Error![]const KeyValue {
    const vec = v orelse return &.{};
    try d.tables(vec.len);
    const out = try d.arena.alloc(KeyValue, vec.len);
    for (out, 0..) |*kv, i| {
        const t = try vec.tableAt(i);
        kv.* = .{ .key = try t.string(0) orelse "", .value = try t.string(1) orelse "" };
        // A reader copies both strings: one long value behind many entries is charged per use.
        try d.charge(kv.key.len +| kv.value.len);
    }
    return out;
}

/// Decodes the `[KeyValue]` vector at field `id` of table `t` (a file footer's
/// `custom_metadata`, say), within the same budget a schema of `t.buf`'s length gets:
/// one long string behind many entries is `error.Malformed`. Strings point into the
/// buffer; the slice is allocated from `arena`.
pub fn decodeKeyValues(arena: std.mem.Allocator, t: fb.Table, id: u16) Error![]const KeyValue {
    var d: Decoder = .{ .arena = arena, .left = budgetFor(t.buf.len) };
    return decodeMetadata(&d, try t.vector(id));
}

fn decodeInt(t: fb.Table) Error!IntType {
    const bits = try t.scalar(i32, 0, 0);
    if (bits != 8 and bits != 16 and bits != 32 and bits != 64) return error.Malformed;
    return .{ .bits = @intCast(bits), .signed = try t.scalar(bool, 1, false) };
}

fn decodeField(d: *Decoder, t: fb.Table, depth: usize) Error!Field {
    const type_id = try t.scalar(u8, 2, 0);
    const tt = try t.table(3);
    const name = try t.string(0) orelse "";
    try d.charge(name.len);
    const ty = try decodeType(type_id, tt);
    if (ty == .timestamp) if (ty.timestamp.tz) |z| try d.charge(z.len);
    var f: Field = .{
        .name = name,
        .nullable = try t.scalar(bool, 1, false),
        .type = ty,
        .children = try decodeFields(d, try t.vector(5), depth + 1),
        .metadata = try decodeMetadata(d, try t.vector(6)),
    };
    if (try t.table(4)) |de| {
        f.dictionary = .{
            .id = try de.scalar(i64, 0, 0),
            .index = if (try de.table(1)) |it| try decodeInt(it) else .{ .bits = 32, .signed = true },
            .ordered = try de.scalar(bool, 2, false),
        };
    }
    return f;
}

fn decodeType(id: u8, tt: ?fb.Table) Error!Type {
    // Every type with parameters needs its table; the parameterless ones may omit it.
    return switch (id) {
        tid.null_ => .null,
        tid.int => .{ .int = try decodeInt(tt orelse return error.Malformed) },
        tid.float => .{ .float = try (tt orelse return error.Malformed).scalar(Precision, 0, .half) },
        tid.binary => .binary,
        tid.utf8 => .utf8,
        tid.bool_ => .bool,
        tid.decimal => blk: {
            const d = tt orelse return error.Malformed;
            const bits = try d.scalar(i32, 2, 128);
            if (bits != 32 and bits != 64 and bits != 128 and bits != 256) return error.Malformed;
            break :blk .{ .decimal = .{ .precision = try d.scalar(i32, 0, 0), .scale = try d.scalar(i32, 1, 0), .bits = bits } };
        },
        tid.date => .{ .date = if (tt) |d| try d.scalar(DateUnit, 0, .millisecond) else .millisecond },
        tid.time => blk: {
            const d = tt orelse return error.Malformed;
            const bits = try d.scalar(i32, 1, 32);
            if (bits != 32 and bits != 64) return error.Malformed;
            break :blk .{ .time = .{ .unit = try d.scalar(TimeUnit, 0, .millisecond), .bits = bits } };
        },
        tid.timestamp => blk: {
            const d = tt orelse return error.Malformed;
            break :blk .{ .timestamp = .{ .unit = try d.scalar(TimeUnit, 0, .second), .tz = try d.string(1) } };
        },
        tid.list => .list,
        tid.struct_ => .@"struct",
        tid.fixed_size_binary => blk: {
            const w = try (tt orelse return error.Malformed).scalar(i32, 0, 0);
            if (w < 0) return error.Malformed;
            break :blk .{ .fixed_size_binary = w };
        },
        tid.fixed_size_list => blk: {
            const n = try (tt orelse return error.Malformed).scalar(i32, 0, 0);
            if (n < 0) return error.Malformed;
            break :blk .{ .fixed_size_list = n };
        },
        tid.duration => .{ .duration = if (tt) |d| try d.scalar(TimeUnit, 0, .millisecond) else .millisecond },
        tid.large_binary => .large_binary,
        tid.large_utf8 => .large_utf8,
        tid.large_list => .large_list,
        tid.run_end_encoded => .run_end_encoded,
        0 => error.Malformed, // NONE
        else => .{ .unsupported = id },
    };
}

// ── encoding ────────────────────────────────────────────────────────────────

/// Builds a `Schema` table; returns its reference.
pub fn encodeSchema(b: *fb.Builder, s: Schema) Error!fb.Ref {
    const fields = try encodeFields(b, s.fields, 0);
    const md = try encodeMetadata(b, s.metadata);
    b.startTable();
    try b.addOffset(1, fields);
    if (md) |m| try b.addOffset(2, m);
    return b.endTable(); // endianness Little = 0 = default, omitted
}

fn encodeFields(b: *fb.Builder, fields: []const Field, depth: usize) Error!fb.Ref {
    if (depth >= max_depth) return error.Unsupported;
    var refs = try b.gpa.alloc(fb.Ref, fields.len);
    defer b.gpa.free(refs);
    for (fields, 0..) |f, i| refs[i] = try encodeField(b, f, depth);
    return b.createOffsetVector(refs);
}

/// Builds a `[KeyValue]` vector (null for none, which a table then omits).
pub fn encodeKeyValues(b: *fb.Builder, md: []const KeyValue) Error!?fb.Ref {
    return encodeMetadata(b, md);
}

fn encodeMetadata(b: *fb.Builder, md: []const KeyValue) Error!?fb.Ref {
    if (md.len == 0) return null;
    var refs = try b.gpa.alloc(fb.Ref, md.len);
    defer b.gpa.free(refs);
    for (md, 0..) |kv, i| {
        const k = try b.createString(kv.key);
        const v = try b.createString(kv.value);
        b.startTable();
        try b.addOffset(0, k);
        try b.addOffset(1, v);
        refs[i] = try b.endTable();
    }
    return try b.createOffsetVector(refs);
}

fn encodeIntTable(b: *fb.Builder, it: IntType) Error!fb.Ref {
    b.startTable();
    try b.addScalarForce(0, i32, it.bits);
    try b.addScalar(1, bool, it.signed, false);
    return b.endTable();
}

fn encodeField(b: *fb.Builder, f: Field, depth: usize) Error!fb.Ref {
    const name = try b.createString(f.name);
    const children = try encodeFields(b, f.children, depth + 1);
    const md = try encodeMetadata(b, f.metadata);
    const type_ref = try encodeTypeTable(b, f.type);
    var dict: ?fb.Ref = null;
    if (f.dictionary) |d| {
        const it = try encodeIntTable(b, d.index);
        b.startTable();
        try b.addScalar(0, i64, d.id, 0);
        try b.addOffset(1, it);
        try b.addScalar(2, bool, d.ordered, false);
        dict = try b.endTable();
    }
    b.startTable();
    try b.addOffset(0, name);
    try b.addScalar(1, bool, f.nullable, false);
    try b.addScalarForce(2, u8, typeId(f.type) orelse return error.Unsupported);
    try b.addOffset(3, type_ref);
    if (dict) |d| try b.addOffset(4, d);
    try b.addOffset(5, children);
    if (md) |m| try b.addOffset(6, m);
    return b.endTable();
}

fn typeId(t: Type) ?u8 {
    return switch (t) {
        .null => tid.null_,
        .int => tid.int,
        .float => tid.float,
        .binary => tid.binary,
        .utf8 => tid.utf8,
        .bool => tid.bool_,
        .decimal => tid.decimal,
        .date => tid.date,
        .time => tid.time,
        .timestamp => tid.timestamp,
        .list => tid.list,
        .@"struct" => tid.struct_,
        .fixed_size_binary => tid.fixed_size_binary,
        .fixed_size_list => tid.fixed_size_list,
        .duration => tid.duration,
        .large_binary => tid.large_binary,
        .large_utf8 => tid.large_utf8,
        .large_list => tid.large_list,
        .run_end_encoded => tid.run_end_encoded,
        .unsupported => null,
    };
}

/// The type's own table (Arrow writes one for every type, an empty one for the parameterless).
fn encodeTypeTable(b: *fb.Builder, t: Type) Error!fb.Ref {
    switch (t) {
        .int => |it| return encodeIntTable(b, it),
        .timestamp => |ts| {
            const tz: ?fb.Ref = if (ts.tz) |z| try b.createString(z) else null;
            b.startTable();
            try b.addScalar(0, TimeUnit, ts.unit, .second);
            if (tz) |z| try b.addOffset(1, z);
            return b.endTable();
        },
        else => {},
    }
    b.startTable();
    switch (t) {
        .float => |p| try b.addScalar(0, Precision, p, .half),
        .decimal => |d| {
            try b.addScalar(0, i32, d.precision, 0);
            try b.addScalar(1, i32, d.scale, 0);
            try b.addScalar(2, i32, d.bits, 128);
        },
        .date => |u| try b.addScalar(0, DateUnit, u, .millisecond),
        .time => |tm| {
            try b.addScalar(0, TimeUnit, tm.unit, .millisecond);
            try b.addScalar(1, i32, tm.bits, 32);
        },
        .fixed_size_binary => |w| try b.addScalar(0, i32, w, 0),
        .fixed_size_list => |n| try b.addScalar(0, i32, n, 0),
        .duration => |u| try b.addScalar(0, TimeUnit, u, .millisecond),
        else => {},
    }
    return b.endTable();
}

// ── the Message envelope ────────────────────────────────────────────────────

pub const HeaderType = enum(u8) { none = 0, schema = 1, dictionary_batch = 2, record_batch = 3, tensor = 4, sparse_tensor = 5, _ };

pub const Message = struct {
    version: MetadataVersion,
    header_type: HeaderType,
    header: ?fb.Table,
    body_length: i64,
};

/// V4 (Arrow 0.8 to 0.17) and V5 (1.0 on) share the layouts this module reads; V1 to V3
/// (pre-0.8) and any value the format does not name are `error.Unsupported`.
pub fn checkVersion(v: MetadataVersion) Error!void {
    if (v != .v4 and v != .v5) return error.Unsupported;
}

/// Reads a `Message` root table from one encapsulated message's metadata bytes;
/// a metadata version other than V4 or V5 is `error.Unsupported`.
pub fn decodeMessage(buf: []const u8) Error!Message {
    const t = try fb.root(buf);
    const body = try t.scalar(i64, 3, 0);
    if (body < 0) return error.Malformed;
    const version = try t.scalar(MetadataVersion, 0, .v1);
    try checkVersion(version);
    return .{
        .version = version,
        .header_type = try t.scalar(HeaderType, 1, .none),
        .header = try t.table(2),
        .body_length = body,
    };
}

/// A finished `Message` buffer holding a schema (owned by `b`).
pub fn encodeSchemaMessage(b: *fb.Builder, s: Schema) Error![]const u8 {
    const sref = try encodeSchema(b, s);
    b.startTable();
    try b.addScalarForce(0, MetadataVersion, .v5);
    try b.addScalarForce(1, HeaderType, .schema);
    try b.addOffset(2, sref);
    try b.addScalar(3, i64, 0, 0);
    return b.finish(try b.endTable());
}

// ── tests ───────────────────────────────────────────────────────────────────

const testing = std.testing;

fn expectSameType(a: Type, b: Type) !void {
    try testing.expectEqual(std.meta.activeTag(a), std.meta.activeTag(b));
    switch (a) {
        .timestamp => |ta| {
            try testing.expectEqual(ta.unit, b.timestamp.unit);
            if (ta.tz) |z| try testing.expectEqualStrings(z, b.timestamp.tz.?) else try testing.expect(b.timestamp.tz == null);
        },
        else => try testing.expect(std.meta.eql(a, b)),
    }
}

fn expectSameFields(a: []const Field, b: []const Field) !void {
    try testing.expectEqual(a.len, b.len);
    for (a, b) |x, y| {
        try testing.expectEqualStrings(x.name, y.name);
        try testing.expectEqual(x.nullable, y.nullable);
        try expectSameType(x.type, y.type);
        try testing.expect(std.meta.eql(x.dictionary, y.dictionary));
        try testing.expectEqual(x.metadata.len, y.metadata.len);
        for (x.metadata, y.metadata) |p, q| {
            try testing.expectEqualStrings(p.key, q.key);
            try testing.expectEqualStrings(p.value, q.value);
        }
        try expectSameFields(x.children, y.children);
    }
}

test "schema message round trip: every supported type, nesting, dictionary, metadata" {
    const item = [_]Field{.{ .name = "item", .type = .{ .int = .{ .bits = 64, .signed = true } } }};
    const kids = [_]Field{
        .{ .name = "a", .nullable = false, .type = .{ .float = .double } },
        .{ .name = "b", .type = .utf8 },
    };
    const fields = [_]Field{
        .{ .name = "n", .type = .null },
        .{ .name = "i8", .type = .{ .int = .{ .bits = 8, .signed = true } } },
        .{ .name = "u64", .nullable = false, .type = .{ .int = .{ .bits = 64, .signed = false } } },
        .{ .name = "f32", .type = .{ .float = .single } },
        .{ .name = "bin", .type = .binary },
        .{ .name = "bool", .type = .bool },
        .{ .name = "dec", .type = .{ .decimal = .{ .precision = 38, .scale = 10 } } },
        .{ .name = "day", .type = .{ .date = .day } },
        .{ .name = "tod", .type = .{ .time = .{ .unit = .nanosecond, .bits = 64 } } },
        .{ .name = "ts", .type = .{ .timestamp = .{ .unit = .microsecond, .tz = "Europe/Prague" } } },
        .{ .name = "ts_naive", .type = .{ .timestamp = .{ .unit = .second } } },
        .{ .name = "list", .type = .list, .children = &item },
        .{ .name = "rec", .type = .@"struct", .children = &kids },
        .{ .name = "fsb", .type = .{ .fixed_size_binary = 16 } },
        .{ .name = "fsl", .type = .{ .fixed_size_list = 3 }, .children = &item },
        .{ .name = "dur", .type = .{ .duration = .nanosecond } },
        .{ .name = "lbin", .type = .large_binary },
        .{ .name = "lutf8", .type = .large_utf8 },
        .{ .name = "llist", .type = .large_list, .children = &item },
        .{ .name = "cat", .type = .utf8, .dictionary = .{ .id = 7, .index = .{ .bits = 16, .signed = true }, .ordered = true }, .metadata = &.{.{ .key = "k", .value = "v" }} },
    };
    const s: Schema = .{ .fields = &fields, .metadata = &.{.{ .key = "pandas", .value = "{}" }} };

    var b = fb.Builder.init(testing.allocator);
    defer b.deinit();
    const buf = try encodeSchemaMessage(&b, s);

    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const m = try decodeMessage(buf);
    try testing.expectEqual(MetadataVersion.v5, m.version);
    try testing.expectEqual(HeaderType.schema, m.header_type);
    const got = try decodeSchema(arena_state.allocator(), m.header.?);
    try expectSameFields(s.fields, got.fields);
    try testing.expectEqualStrings("pandas", got.metadata[0].key);
}

test "decoder: hostile schemas are errors, never crashes (every truncation and byte flip)" {
    const kids = [_]Field{.{ .name = "x", .type = .{ .timestamp = .{ .unit = .millisecond, .tz = "UTC" } } }};
    const fields = [_]Field{
        .{ .name = "rec", .type = .@"struct", .children = &kids },
        .{ .name = "cat", .type = .utf8, .dictionary = .{ .id = 1 } },
    };
    var b = fb.Builder.init(testing.allocator);
    defer b.deinit();
    const good = try encodeSchemaMessage(&b, .{ .fields = &fields });
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const walk = struct {
        fn f(arena: std.mem.Allocator, buf: []const u8) void {
            const m = decodeMessage(buf) catch return;
            const h = m.header orelse return;
            _ = decodeSchema(arena, h) catch {};
        }
    }.f;
    for (0..good.len) |n| walk(arena_state.allocator(), good[0..n]);
    const copy = try testing.allocator.alloc(u8, good.len);
    defer testing.allocator.free(copy);
    for (0..good.len) |i| {
        for ([_]u8{ 0x00, 0x01, 0x40, 0x7f, 0x80, 0xff }) |v| {
            @memcpy(copy, good);
            copy[i] = v;
            walk(arena_state.allocator(), copy);
        }
    }
}

test "nesting deeper than max_depth is refused on decode and on encode" {
    // 70 nested struct fields, built by hand innermost first (the encoder itself refuses past max_depth).
    var b = fb.Builder.init(testing.allocator);
    defer b.deinit();
    var inner: ?fb.Ref = null;
    for (0..70) |_| {
        const kids = if (inner) |r| try b.createOffsetVector(&.{r}) else try b.createOffsetVector(&.{});
        b.startTable();
        try b.addScalarForce(2, u8, tid.struct_);
        try b.addOffset(5, kids);
        inner = try b.endTable();
    }
    const top = try b.createOffsetVector(&.{inner.?});
    b.startTable();
    try b.addOffset(1, top);
    const buf = try b.finish(try b.endTable());
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    try testing.expectError(error.Malformed, decodeSchema(arena_state.allocator(), try fb.root(buf)));

    // The same depth through the encoder.
    var chain: [70]Field = undefined;
    for (&chain, 0..) |*f, i| f.* = .{ .name = "s", .type = .@"struct", .children = if (i + 1 < chain.len) chain[i + 1 ..][0..1] else &.{} };
    var b2 = fb.Builder.init(testing.allocator);
    defer b2.deinit();
    try testing.expectError(error.Unsupported, encodeSchemaMessage(&b2, .{ .fields = chain[0..1] }));
}

test "max_depth is exact: 63 nested levels decode and encode, 64 do not" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    for ([_]struct { levels: usize, ok: bool }{ .{ .levels = 63, .ok = true }, .{ .levels = 64, .ok = false } }) |c| {
        var b = fb.Builder.init(testing.allocator);
        defer b.deinit();
        var inner: ?fb.Ref = null;
        for (0..c.levels) |_| {
            const kids = if (inner) |r| try b.createOffsetVector(&.{r}) else try b.createOffsetVector(&.{});
            b.startTable();
            try b.addScalarForce(2, u8, tid.struct_);
            try b.addOffset(5, kids);
            inner = try b.endTable();
        }
        const top = try b.createOffsetVector(&.{inner.?});
        b.startTable();
        try b.addOffset(1, top);
        const buf = try b.finish(try b.endTable());
        const got = decodeSchema(arena_state.allocator(), try fb.root(buf));
        if (c.ok) _ = try got else try testing.expectError(error.Malformed, got);

        var chain: [64]Field = undefined;
        const n = c.levels;
        for (chain[0..n], 0..) |*f, i| f.* = .{ .name = "s", .type = .@"struct", .children = if (i + 1 < n) chain[i + 1 ..][0..1] else &.{} };
        var b2 = fb.Builder.init(testing.allocator);
        defer b2.deinit();
        const enc = encodeSchemaMessage(&b2, .{ .fields = chain[0..1] });
        if (c.ok) _ = try enc else try testing.expectError(error.Unsupported, enc);
    }
}

test "decoder: the budget refuses exactly what it cannot pay" {
    var d: Decoder = .{ .arena = testing.allocator, .left = 16 };
    try d.charge(16);
    try testing.expectError(error.Malformed, d.charge(1));
}

test "decoder: big-endian schemas, type parameters the format does not allow, absent type tables" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    {
        var b = fb.Builder.init(testing.allocator);
        defer b.deinit();
        const empty = try b.createOffsetVector(&.{});
        b.startTable();
        try b.addScalar(0, i16, 1, 0); // endianness Big
        try b.addOffset(1, empty);
        const buf = try b.finish(try b.endTable());
        try testing.expectError(error.Unsupported, decodeSchema(arena_state.allocator(), try fb.root(buf)));
    }
    const Bad = struct { id: u8, field: u16, value: i32 };
    for ([_]Bad{
        .{ .id = tid.decimal, .field = 2, .value = 100 }, // bitWidth
        .{ .id = tid.time, .field = 1, .value = 16 }, // bitWidth
        .{ .id = tid.fixed_size_binary, .field = 0, .value = -1 },
        .{ .id = tid.fixed_size_list, .field = 0, .value = -1 },
    }) |c| {
        var b = fb.Builder.init(testing.allocator);
        defer b.deinit();
        b.startTable();
        try b.addScalarForce(c.field, i32, c.value);
        const buf = try b.finish(try b.endTable());
        try testing.expectError(error.Malformed, decodeType(c.id, try fb.root(buf)));
    }
    // Without their tables Date and Duration take Schema.fbs' defaults; NONE is no type.
    try testing.expectEqual(DateUnit.millisecond, (try decodeType(tid.date, null)).date);
    try testing.expectEqual(TimeUnit.millisecond, (try decodeType(tid.duration, null)).duration);
    try testing.expectError(error.Malformed, decodeType(0, null));
}

test "decoder: a dictionary without indexType is int32; shared metadata and a shared zone are charged per use" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    {
        var b = fb.Builder.init(testing.allocator);
        defer b.deinit();
        b.startTable();
        try b.addScalar(0, i64, 3, 0);
        const de = try b.endTable(); // DictionaryEncoding: id 3, no indexType
        b.startTable();
        const tt = try b.endTable(); // Utf8
        b.startTable();
        try b.addScalarForce(2, u8, tid.utf8);
        try b.addOffset(3, tt);
        try b.addOffset(4, de);
        const field = try b.endTable();
        const fields = try b.createOffsetVector(&.{field});
        b.startTable();
        try b.addOffset(1, fields);
        const buf = try b.finish(try b.endTable());
        const s = try decodeSchema(arena, try fb.root(buf));
        const d = s.fields[0].dictionary.?;
        try testing.expectEqual(@as(i64, 3), d.id);
        try testing.expectEqual(IntType{ .bits = 32, .signed = true }, d.index);
    }
    {
        // One KeyValue table named by 1000 metadata entries: 4 bytes each, a table each to decode.
        var b = fb.Builder.init(testing.allocator);
        defer b.deinit();
        const k = try b.createString("k");
        b.startTable();
        try b.addOffset(0, k);
        const kv = try b.endTable();
        const refs: [1000]fb.Ref = @splat(kv);
        const md = try b.createOffsetVector(&refs);
        const empty = try b.createOffsetVector(&.{});
        b.startTable();
        try b.addOffset(1, empty);
        try b.addOffset(2, md);
        const buf = try b.finish(try b.endTable());
        try testing.expectError(error.Malformed, decodeSchema(arena, try fb.root(buf)));
    }
    {
        // 50 fields of their own, all naming one Timestamp type whose zone is 1000 bytes.
        var b = fb.Builder.init(testing.allocator);
        defer b.deinit();
        const zone: [1000]u8 = @splat('z');
        const z = try b.createString(&zone);
        b.startTable();
        try b.addOffset(1, z);
        const ts = try b.endTable();
        var refs: [50]fb.Ref = undefined;
        for (&refs) |*r| {
            b.startTable();
            try b.addScalarForce(2, u8, tid.timestamp);
            try b.addOffset(3, ts);
            r.* = try b.endTable();
        }
        const fields = try b.createOffsetVector(&refs);
        b.startTable();
        try b.addOffset(1, fields);
        const buf = try b.finish(try b.endTable());
        try testing.expectError(error.Malformed, decodeSchema(arena, try fb.root(buf)));
    }
}

test "decoder: a Message without a version is V1, which is Unsupported" {
    var b = fb.Builder.init(testing.allocator);
    defer b.deinit();
    b.startTable();
    try b.addScalarForce(1, HeaderType, .schema);
    const buf = try b.finish(try b.endTable());
    try testing.expectError(error.Unsupported, decodeMessage(buf));
}
