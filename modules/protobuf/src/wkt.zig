// SPDX-License-Identifier: MIT

//! Well-known types (`google/protobuf/*.proto`) as ordinary message structs,
//! field for field as the published `.proto` files declare them, so they
//! encode and decode through the same codec as any other message and are
//! byte-compatible with every other implementation (checked against the
//! reference's own `timestamp_pb2`, `struct_pb2`, … in `wkt_test.zig`).
//!
//! The JSON mappings these types are best known for (RFC 3339 timestamps,
//! `"1.5s"` durations, `Struct` as a JSON object) are not here: they belong to
//! the canonical JSON mapping, which this module does not implement (SPEC.md).

const std = @import("std");
const schema = @import("schema.zig");
const encode_mod = @import("encode.zig");
const decode_mod = @import("decode.zig");
const Field = schema.Field;

/// `google.protobuf.Timestamp`: seconds since the Unix epoch plus a
/// non-negative fraction, `nanos` in `0..999_999_999` even before 1970.
pub const Timestamp = struct {
    seconds: i64 = 0,
    nanos: i32 = 0,

    pub const pb_fields = .{
        .seconds = Field{ .number = 1, .kind = .int64 },
        .nanos = Field{ .number = 2, .kind = .int32 },
    };

    /// 0001-01-01T00:00:00Z and 9999-12-31T23:59:59Z, the range
    /// `timestamp.proto` restricts `seconds` to.
    pub const min_seconds: i64 = -62_135_596_800;
    pub const max_seconds: i64 = 253_402_300_799;

    pub fn isValid(self: Timestamp) bool {
        return self.seconds >= min_seconds and self.seconds <= max_seconds and
            self.nanos >= 0 and self.nanos <= 999_999_999;
    }

    /// From nanoseconds since the epoch; the fraction is floored, so
    /// -1 ns is `{ -1 s, 999_999_999 ns }`.
    pub fn fromUnixNanos(ns: i128) Timestamp {
        return .{
            .seconds = @intCast(@divFloor(ns, std.time.ns_per_s)),
            .nanos = @intCast(@mod(ns, std.time.ns_per_s)),
        };
    }

    pub fn toUnixNanos(self: Timestamp) i128 {
        return @as(i128, self.seconds) * std.time.ns_per_s + self.nanos;
    }
};

/// `google.protobuf.Duration`: a signed span; `seconds` within ±10 000 years
/// and `nanos` of the same sign as `seconds` (or either sign when `seconds`
/// is 0).
pub const Duration = struct {
    seconds: i64 = 0,
    nanos: i32 = 0,

    pub const pb_fields = .{
        .seconds = Field{ .number = 1, .kind = .int64 },
        .nanos = Field{ .number = 2, .kind = .int32 },
    };

    pub const max_seconds: i64 = 315_576_000_000;

    pub fn isValid(self: Duration) bool {
        if (self.seconds < -max_seconds or self.seconds > max_seconds) return false;
        if (self.nanos < -999_999_999 or self.nanos > 999_999_999) return false;
        if (self.seconds > 0 and self.nanos < 0) return false;
        if (self.seconds < 0 and self.nanos > 0) return false;
        return true;
    }

    /// From a nanosecond count; both parts truncate toward zero, so they
    /// share its sign.
    pub fn fromNanos(ns: i128) Duration {
        return .{
            .seconds = @intCast(@divTrunc(ns, std.time.ns_per_s)),
            .nanos = @intCast(@rem(ns, std.time.ns_per_s)),
        };
    }

    pub fn toNanos(self: Duration) i128 {
        return @as(i128, self.seconds) * std.time.ns_per_s + self.nanos;
    }
};

/// `google.protobuf.Empty`.
pub const Empty = struct {
    pub const pb_fields = .{};
};

fn Wrapper(comptime kind: schema.Kind, comptime T: type, comptime default: T) type {
    return struct {
        value: T = default,
        pub const pb_fields = .{ .value = Field{ .number = 1, .kind = kind } };
    };
}

/// `google/protobuf/wrappers.proto`: a scalar with presence, as a message.
pub const DoubleValue = Wrapper(.double, f64, 0);
pub const FloatValue = Wrapper(.float, f32, 0);
pub const Int64Value = Wrapper(.int64, i64, 0);
pub const UInt64Value = Wrapper(.uint64, u64, 0);
pub const Int32Value = Wrapper(.int32, i32, 0);
pub const UInt32Value = Wrapper(.uint32, u32, 0);
pub const BoolValue = Wrapper(.bool, bool, false);
pub const StringValue = Wrapper(.string, []const u8, "");
pub const BytesValue = Wrapper(.bytes, []const u8, "");

/// `google.protobuf.FieldMask`.
pub const FieldMask = struct {
    paths: []const []const u8 = &.{},
    pub const pb_fields = .{ .paths = Field{ .number = 1, .kind = .string } };
};

/// `google.protobuf.Any`: a message of any type, as `type_url` + its bytes.
pub const Any = struct {
    type_url: []const u8 = "",
    value: []const u8 = "",

    pub const pb_fields = .{
        .type_url = Field{ .number = 1, .kind = .string },
        .value = Field{ .number = 2, .kind = .bytes },
    };

    pub const default_prefix = "type.googleapis.com/";

    /// Pack `msg` under `type_url` (e.g. `"type.googleapis.com/acme.Order"`;
    /// borrowed, not copied). `value` is `gpa`-owned: free it.
    pub fn pack(gpa: std.mem.Allocator, msg: anytype, type_url: []const u8, options: encode_mod.Options) (encode_mod.Error || std.mem.Allocator.Error)!Any {
        return .{ .type_url = type_url, .value = try encode_mod.encodeAlloc(gpa, msg, options) };
    }

    /// The full type name: what follows the last `/` of `type_url`.
    pub fn typeName(self: Any) []const u8 {
        const at = std.mem.lastIndexOfScalar(u8, self.type_url, '/') orelse return self.type_url;
        return self.type_url[at + 1 ..];
    }

    /// Does this `Any` hold a message of full name `full_name`
    /// (`"acme.Order"`)? The prefix before the last `/` is not compared.
    pub fn is(self: Any, full_name: []const u8) bool {
        return std.mem.eql(u8, self.typeName(), full_name);
    }

    /// Decode the packed message as `T`, after checking it is `full_name`.
    pub fn unpack(self: Any, comptime T: type, gpa: std.mem.Allocator, full_name: []const u8, options: decode_mod.Options) (decode_mod.Error || error{TypeMismatch})!decode_mod.Decoded(T) {
        if (!self.is(full_name)) return error.TypeMismatch;
        return decode_mod.decode(T, gpa, self.value, options);
    }
};

/// `google.protobuf.NullValue`.
pub const NullValue = enum(i32) { null_value = 0, _ };

/// `google.protobuf.Struct`: a JSON object — `map<string, Value> fields = 1`.
pub const Struct = struct {
    fields: []const FieldsEntry = &.{},
    pub const pb_fields = .{ .fields = Field{ .number = 1, .kind = .message } };

    pub const FieldsEntry = struct {
        key: []const u8 = "",
        value: Value = .{},
        pub const pb_map_entry = true;
        pub const pb_fields = .{
            .key = Field{ .number = 1, .kind = .string },
            .value = Field{ .number = 2, .kind = .message },
        };
    };
};

/// `google.protobuf.Value`: one JSON value, `oneof kind`.
pub const Value = struct {
    kind: ?Kind = null,
    pub const pb_fields = .{ .kind = schema.oneof };

    pub const Kind = union(enum) {
        null_value: NullValue,
        number_value: f64,
        string_value: []const u8,
        bool_value: bool,
        struct_value: Struct,
        list_value: ListValue,
        pub const pb_fields = .{
            .null_value = Field{ .number = 1, .kind = .@"enum" },
            .number_value = Field{ .number = 2, .kind = .double },
            .string_value = Field{ .number = 3, .kind = .string },
            .bool_value = Field{ .number = 4, .kind = .bool },
            .struct_value = Field{ .number = 5, .kind = .message },
            .list_value = Field{ .number = 6, .kind = .message },
        };
    };
};

/// `google.protobuf.ListValue`: a JSON array — `repeated Value values = 1`.
pub const ListValue = struct {
    values: []const Value = &.{},
    pub const pb_fields = .{ .values = Field{ .number = 1, .kind = .message } };
};
