// SPDX-License-Identifier: MIT
//! Tests for `oneof`, `map<K, V>` and the well-known types (2026-10-04).
//!
//! Every expected byte string comes from the reference implementation
//! (Python `protobuf`, driven as a black box by `tools/gen_core_vectors.py`,
//! frozen in `testdata/core_vectors.zig`) or is derived by hand from the
//! encoding spec / the `google/protobuf/*.proto` comments, as each test says.

const std = @import("std");
const testing = std.testing;
const pb = @import("root.zig");
const Field = pb.Field;
const wkt = pb.wkt;
const cv = @import("testdata/core_vectors.zig");

// Mirror of `gen_core_vectors.py`'s `core.Sub` / `core.C`, field for field.
pub const Sub = struct {
    x: i32 = 0,
    y: i32 = 0,
    pub const pb_fields = .{
        .x = Field{ .number = 1, .kind = .int32 },
        .y = Field{ .number = 2, .kind = .int32 },
    };
};

pub const Choice = union(enum) {
    a: i32,
    b: []const u8,
    c: Sub,
    d: []const u8,
    pub const pb_fields = .{
        .a = Field{ .number = 5, .kind = .int32 },
        .b = Field{ .number = 6, .kind = .string },
        .c = Field{ .number = 7, .kind = .message },
        .d = Field{ .number = 8, .kind = .bytes },
    };
};

pub const Labels = pb.MapEntry(.string, []const u8, .int32, i32);
pub const Names = pb.MapEntry(.int32, i32, .string, []const u8);
pub const Subs = pb.MapEntry(.sint64, i64, .message, Sub);
pub const Flags = pb.MapEntry(.bool, bool, .bytes, []const u8);

pub const C = struct {
    labels: []const Labels = &.{},
    names: []const Names = &.{},
    subs: []const Subs = &.{},
    flags: []const Flags = &.{},
    choice: ?Choice = null,
    tail: i32 = 0,
    // The reference keeps unknown fields; so does this mirror.
    unknown: pb.Unknown = .empty,
    pub const pb_fields = .{
        .labels = Field{ .number = 1, .kind = .message },
        .names = Field{ .number = 2, .kind = .message },
        .subs = Field{ .number = 3, .kind = .message },
        .flags = Field{ .number = 4, .kind = .message },
        .choice = pb.oneof,
        .tail = Field{ .number = 9, .kind = .int32 },
    };
};

fn unhex(a: std.mem.Allocator, h: []const u8) ![]u8 {
    const out = try a.alloc(u8, h.len / 2);
    _ = try std.fmt.hexToBytes(out, h);
    return out;
}

fn expectEncodes(a: std.mem.Allocator, value: anytype, want_hex: []const u8) !void {
    const want = try unhex(a, want_hex);
    defer a.free(want);
    const got = try pb.encodeAlloc(a, value, .{});
    defer a.free(got);
    try testing.expectEqualSlices(u8, want, got);
    // The allocation-free path agrees.
    var buf: [512]u8 = undefined;
    const n = try pb.encodeInto(&buf, value, .{});
    try testing.expectEqualSlices(u8, want, buf[0..n]);
}

fn roundTrip(comptime T: type, a: std.mem.Allocator, hex: []const u8) !void {
    const bytes = try unhex(a, hex);
    defer a.free(bytes);
    var d = try pb.decode(T, a, bytes, .{});
    defer d.deinit();
    try expectEncodes(a, d.value, hex);
}

test "schema: a oneof's members are fields of their own, tied to the group" {
    const t = comptime pb.infos(C);
    // 4 maps + 4 oneof members + tail.
    try testing.expectEqual(@as(usize, 9), t.len);
    comptime var members = 0;
    inline for (t) |i| if (i.card == .oneof) {
        members += 1;
        try testing.expectEqualStrings("choice", i.oneof_field);
    };
    try testing.expectEqual(4, members);
    try testing.expect(pb.isMapEntry(Labels));
    try testing.expect(!pb.isMapEntry(Sub));
}

test "reference verdicts: maps and a oneof, canonical and hostile shapes" {
    const a = testing.allocator;
    for (cv.c_cases) |c| {
        const input = try unhex(a, c.input);
        defer a.free(input);
        var d = pb.decode(C, a, input, .{}) catch |e| {
            std.debug.print("case '{s}': {t}\n", .{ c.what, e });
            return e;
        };
        defer d.deinit();
        const want = try unhex(a, c.canonical);
        defer a.free(want);
        const got = try pb.encodeAlloc(a, d.value, .{});
        defer a.free(got);
        testing.expectEqualSlices(u8, want, got) catch |e| {
            std.debug.print("case '{s}'\n", .{c.what});
            return e;
        };
    }
    try testing.expectEqual(@as(usize, 25), cv.c_cases.len);
}

test "decode: what the reference verdicts mean, field by field" {
    const a = testing.allocator;
    // "duplicate key": a=1, b=2, a=3 -> [a: 3, b: 2] (first position, last value).
    const dup = try unhex(a, cv.c_cases[9].input);
    defer a.free(dup);
    var d = try pb.decode(C, a, dup, .{});
    defer d.deinit();
    try testing.expectEqual(@as(usize, 2), d.value.labels.len);
    try testing.expectEqualStrings("a", d.value.labels[0].key);
    try testing.expectEqual(@as(i32, 3), d.value.labels[0].value);
    try testing.expectEqual(@as(i32, 2), d.value.labels[1].value);
    // "another member in between restarts the message": c{x:1}, a=7, c{y:5} -> c{y:5}.
    const re = try unhex(a, cv.c_cases[20].input);
    defer a.free(re);
    var d2 = try pb.decode(C, a, re, .{});
    defer d2.deinit();
    try testing.expectEqual(@as(i32, 0), d2.value.choice.?.c.x);
    try testing.expectEqual(@as(i32, 5), d2.value.choice.?.c.y);
    // "message member merges with itself": c{x:1}, c{y:5} -> c{x:1, y:5}.
    const mg = try unhex(a, cv.c_cases[19].input);
    defer a.free(mg);
    var d3 = try pb.decode(C, a, mg, .{});
    defer d3.deinit();
    try testing.expectEqual(Sub{ .x = 1, .y = 5 }, d3.value.choice.?.c);
    // "scalar after message": a = 9 wins.
    const sm = try unhex(a, cv.c_cases[21].input);
    defer a.free(sm);
    var d4 = try pb.decode(C, a, sm, .{});
    defer d4.deinit();
    try testing.expectEqual(@as(i32, 9), d4.value.choice.?.a);
}

test "encode: three messages built field for field (reference bytes)" {
    const a = testing.allocator;
    // labels {zeta: 1, alpha: 2} (insertion order), a = 7.
    try expectEncodes(a, C{
        .labels = &.{ .{ .key = "zeta", .value = 1 }, .{ .key = "alpha", .value = 2 } },
        .choice = .{ .a = 7 },
    }, cv.enc_map_and_oneof);
    // subs {3: {x: 4}}, c = {} (set, empty), tail = -1.
    try expectEncodes(a, C{
        .subs = &.{.{ .key = 3, .value = .{ .x = 4 } }},
        .choice = .{ .c = .{} },
        .tail = -1,
    }, cv.enc_message_values);
    // flags {false: ""}, names {0: ""}, b = "hi": default keys and values
    // are written inside an entry.
    try expectEncodes(a, C{
        .names = &.{.{ .key = 0, .value = "" }},
        .flags = &.{.{ .key = false, .value = "" }},
        .choice = .{ .b = "hi" },
    }, cv.enc_defaults_in_entries);
}

test "sortMap: the reference's deterministic order (derived from the entries' own bytes)" {
    const a = testing.allocator;
    var entries = [_]Labels{ .{ .key = "b", .value = 5 }, .{ .key = "a", .value = 0 }, .{ .key = "", .value = 7 } };
    pb.sortMap(Labels, &entries);
    // "" -> 0a 04 0a00 1007, "a" -> 0a 05 0a0161 1000, "b" -> 0a 05 0a0162 1005.
    try expectEncodes(a, C{ .labels = &entries }, "0a040a001007" ++ "0a050a01611000" ++ "0a050a01621005");
    var ints = [_]Names{ .{ .key = 300 }, .{ .key = -1 }, .{ .key = 0 } };
    pb.sortMap(Names, &ints);
    try testing.expectEqual(@as(i32, -1), ints[0].key);
    try testing.expectEqual(@as(i32, 300), ints[2].key);
}

test "decode: a map with many duplicate keys stays linear-ish and exact" {
    // 2000 entries over 10 keys: the dedupe keeps 10, each with its last value.
    const a = testing.allocator;
    var list: std.ArrayList(Names) = .empty;
    defer list.deinit(a);
    for (0..2000) |i| try list.append(a, .{ .key = @intCast(i % 10), .value = if (i >= 1990) "last" else "x" });
    const bytes = try pb.encodeAlloc(a, C{ .names = list.items }, .{});
    defer a.free(bytes);
    var d = try pb.decode(C, a, bytes, .{});
    defer d.deinit();
    try testing.expectEqual(@as(usize, 10), d.value.names.len);
    for (d.value.names, 0..) |e, i| {
        try testing.expectEqual(@as(i32, @intCast(i)), e.key);
        try testing.expectEqualStrings("last", e.value);
    }
}

// ── well-known types ───────────────────────────────────────────────────────

test "wkt: Timestamp and Duration bytes match the reference" {
    const a = testing.allocator;
    for (cv.timestamps) |t| try expectEncodes(a, wkt.Timestamp{ .seconds = t.seconds, .nanos = t.nanos }, t.hex);
    for (cv.durations) |t| try expectEncodes(a, wkt.Duration{ .seconds = t.seconds, .nanos = t.nanos }, t.hex);
    for (cv.timestamps) |t| try roundTrip(wkt.Timestamp, a, t.hex);
}

test "wkt: nanosecond splits match the reference's FromNanoseconds" {
    for (cv.timestamp_from_nanos) |s| {
        const t = wkt.Timestamp.fromUnixNanos(s.ns);
        try testing.expectEqual(s.seconds, t.seconds);
        try testing.expectEqual(s.nanos, t.nanos);
        try testing.expectEqual(s.ns, t.toUnixNanos());
    }
    for (cv.duration_from_nanos) |s| {
        const d = wkt.Duration.fromNanos(s.ns);
        try testing.expectEqual(s.seconds, d.seconds);
        try testing.expectEqual(s.nanos, d.nanos);
        try testing.expectEqual(s.ns, d.toNanos());
    }
}

test "wkt: validity at the limits timestamp.proto / duration.proto state" {
    const T = wkt.Timestamp;
    try testing.expect((T{ .seconds = T.min_seconds }).isValid());
    try testing.expect(!(T{ .seconds = T.min_seconds - 1 }).isValid());
    try testing.expect((T{ .seconds = T.max_seconds, .nanos = 999_999_999 }).isValid());
    try testing.expect(!(T{ .seconds = T.max_seconds + 1 }).isValid());
    try testing.expect(!(T{ .nanos = -1 }).isValid());
    try testing.expect(!(T{ .nanos = 1_000_000_000 }).isValid());
    const D = wkt.Duration;
    try testing.expect((D{ .seconds = D.max_seconds, .nanos = 999_999_999 }).isValid());
    try testing.expect(!(D{ .seconds = D.max_seconds + 1 }).isValid());
    try testing.expect(!(D{ .seconds = -D.max_seconds - 1 }).isValid());
    try testing.expect((D{ .seconds = -D.max_seconds, .nanos = -999_999_999 }).isValid());
    try testing.expect(!(D{ .nanos = 1_000_000_000 }).isValid());
    try testing.expect(!(D{ .nanos = -1_000_000_000 }).isValid());
    // Sign agreement: nanos must not oppose a non-zero seconds.
    try testing.expect(!(D{ .seconds = 1, .nanos = -1 }).isValid());
    try testing.expect(!(D{ .seconds = -1, .nanos = 1 }).isValid());
    try testing.expect((D{ .seconds = 0, .nanos = -1 }).isValid());
    try testing.expect((D{ .seconds = 0, .nanos = 1 }).isValid());
}

test "wkt: wrappers, FieldMask, Empty match the reference" {
    const a = testing.allocator;
    try expectEncodes(a, wkt.DoubleValue{ .value = -2.5 }, cv.wrap_double);
    try expectEncodes(a, wkt.FloatValue{ .value = 1.5 }, cv.wrap_float);
    try expectEncodes(a, wkt.Int64Value{ .value = -3 }, cv.wrap_int64);
    try expectEncodes(a, wkt.UInt64Value{ .value = std.math.maxInt(u64) }, cv.wrap_uint64);
    try expectEncodes(a, wkt.Int32Value{ .value = -1 }, cv.wrap_int32);
    try expectEncodes(a, wkt.UInt32Value{ .value = 300 }, cv.wrap_uint32);
    try expectEncodes(a, wkt.BoolValue{ .value = true }, cv.wrap_bool);
    try expectEncodes(a, wkt.StringValue{ .value = "h\u{e9}" }, cv.wrap_string);
    try expectEncodes(a, wkt.BytesValue{ .value = "\x00\x01" }, cv.wrap_bytes);
    try expectEncodes(a, wkt.Int32Value{}, cv.wrap_zero);
    try expectEncodes(a, wkt.FieldMask{ .paths = &.{ "a.b", "c" } }, cv.field_mask);
    try expectEncodes(a, wkt.Empty{}, cv.empty);
}

test "wkt: Any packs, names and unpacks like the reference" {
    const a = testing.allocator;
    const any = try wkt.Any.pack(a, wkt.Timestamp{ .seconds = 5, .nanos = 6 }, cv.any_type_url, .{});
    defer a.free(any.value);
    try expectEncodes(a, any, cv.any_timestamp);
    try testing.expectEqualStrings("google.protobuf.Timestamp", any.typeName());
    try testing.expect(any.is("google.protobuf.Timestamp"));
    try testing.expect(!any.is("protobuf.Timestamp"));
    var t = try any.unpack(wkt.Timestamp, a, "google.protobuf.Timestamp", .{});
    defer t.deinit();
    try testing.expectEqual(@as(i32, 6), t.value.nanos);
    try testing.expectError(error.TypeMismatch, any.unpack(wkt.Duration, a, "google.protobuf.Duration", .{}));
    // A type_url without a '/' is its own name.
    try testing.expectEqualStrings("x.Y", (wkt.Any{ .type_url = "x.Y" }).typeName());
}

test "wkt: Struct / Value / ListValue from the reference decode and re-encode" {
    const a = testing.allocator;
    try roundTrip(wkt.Struct, a, cv.struct_doc);
    try roundTrip(wkt.ListValue, a, cv.list_value);
    // {"name": "x", "n": 1.5, "ok": true, "nil": null, "list": [1, "two", [], {}], "obj": {"k": false}}
    const bytes = try unhex(a, cv.struct_doc);
    defer a.free(bytes);
    var d = try pb.decode(wkt.Struct, a, bytes, .{});
    defer d.deinit();
    const f = d.value.fields;
    try testing.expectEqual(@as(usize, 6), f.len);
    try testing.expectEqualStrings("name", f[0].key);
    try testing.expectEqualStrings("x", f[0].value.kind.?.string_value);
    try testing.expectEqual(@as(f64, 1.5), f[1].value.kind.?.number_value);
    try testing.expect(f[2].value.kind.?.bool_value);
    try testing.expectEqual(wkt.NullValue.null_value, f[3].value.kind.?.null_value);
    const list = f[4].value.kind.?.list_value.values;
    try testing.expectEqual(@as(usize, 4), list.len);
    try testing.expectEqualStrings("two", list[1].kind.?.string_value);
    try testing.expectEqual(@as(usize, 0), list[2].kind.?.list_value.values.len);
    try testing.expectEqual(@as(usize, 0), list[3].kind.?.struct_value.fields.len);
    try testing.expect(!f[5].value.kind.?.struct_value.fields[0].value.kind.?.bool_value);
}

test "oneof/map decode allocates nothing that escapes the arena (allocation failures)" {
    const bytes = comptime blk: {
        const h = "0a050a016110010a050a01621002" ++ "3a0208013a021005" ++ "1a0a08021202080112021005";
        var out: [h.len / 2]u8 = undefined;
        _ = std.fmt.hexToBytes(&out, h) catch unreachable;
        break :blk out;
    };
    try testing.checkAllAllocationFailures(testing.allocator, struct {
        fn f(a: std.mem.Allocator) !void {
            var d = try pb.decode(C, a, &bytes, .{});
            d.deinit();
        }
    }.f, .{});
}

// ── tests asked for by the 2026-10-04 mutation run ─────────────────────────

const TwoMsgs = struct {
    pick: ?Pick = null,
    pub const pb_fields = .{ .pick = pb.oneof };
    pub const Pick = union(enum) {
        p: Sub,
        q: Sub,
        pub const pb_fields = .{
            .p = Field{ .number = 1, .kind = .message },
            .q = Field{ .number = 2, .kind = .message },
        };
    };
};

test "oneof: switching between two MESSAGE members drops the earlier payload" {
    // p{x:1}, q{x:2}, p{y:5}: the spec's last-member rule gives p, and only
    // a member that is still set merges, so p is {y:5} alone — 0a 02 1005.
    const a = testing.allocator;
    const input = try unhex(a, "0a020801" ++ "12020802" ++ "0a021005");
    defer a.free(input);
    var d = try pb.decode(TwoMsgs, a, input, .{});
    defer d.deinit();
    try testing.expectEqual(Sub{ .y = 5 }, d.value.pick.?.p);
    try expectEncodes(a, d.value, "0a021005");
}

test "sortMap: bool keys sort false before true (the reference's order)" {
    var flags = [_]Flags{ .{ .key = true, .value = "t" }, .{ .key = false, .value = "f" } };
    pb.sortMap(Flags, &flags);
    try testing.expect(!flags[0].key);
    try testing.expect(flags[1].key);
}

test "Any: the type name is the LAST path segment of type_url" {
    // google/protobuf/any.proto: "the last segment of the URL's path must
    // represent the fully qualified name of the type".
    const any: wkt.Any = .{ .type_url = "example.com/types/acme.Order" };
    try testing.expectEqualStrings("acme.Order", any.typeName());
    try testing.expect(any.is("acme.Order"));
}
