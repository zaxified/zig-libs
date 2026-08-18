// SPDX-License-Identifier: MIT
//! protobuf — Protocol Buffers **wire format** (proto3), encode and decode,
//! with the schema derived at comptime from ordinary Zig structs.
//!
//! There is no `.proto` compiler and no generated code here: a message is a
//! plain struct that declares `pub const pb_fields`, and the codec is
//! specialised from `@typeInfo` at compile time. The descriptor names the
//! proto type (`.int32`, `.sint64`, `.string`, `.message`, …) and the Zig
//! type carries the cardinality — `T` implicit presence, `?T` explicit
//! presence, `[]const T` repeated.
//!
//! ```zig
//! const protobuf = @import("protobuf");
//!
//! const Point = struct {
//!     x: i32 = 0,
//!     y: i32 = 0,
//!     label: []const u8 = "",
//!     pub const pb_fields = .{
//!         .x     = protobuf.Field{ .number = 1, .kind = .sint32 },
//!         .y     = protobuf.Field{ .number = 2, .kind = .sint32 },
//!         .label = protobuf.Field{ .number = 3, .kind = .string },
//!     };
//! };
//!
//! const bytes = try protobuf.encodeAlloc(gpa, Point{ .x = -3, .y = 7 }, .{});
//! defer gpa.free(bytes);
//!
//! var decoded = try protobuf.decode(Point, gpa, bytes, .{});
//! defer decoded.deinit();
//! ```
//!
//! Untrusted input is the design centre: every length-delimited field's
//! declared length is validated against the bytes actually remaining before
//! it can size an allocation or bound a loop, and embedded-message nesting
//! is capped (`DecodeOptions.max_depth`). See SPEC.md for the threat model
//! and for what is deliberately not implemented (groups, maps, Any/JSON
//! mapping, `.proto` code generation).

const std = @import("std");

pub const meta = .{
    .targets = .{.linux64},
    .platform = .any,
    .role = .codec,
    .concurrency = .reentrant,
    .model_after = "protocolbuffers/protobuf (C++/Python reference implementation) + the published wire-format spec",
    .deps = .{}, // std only
};

const schema = @import("schema.zig");
const wire_mod = @import("wire.zig");
const encode_mod = @import("encode.zig");
const decode_mod = @import("decode.zig");

// ── schema ──────────────────────────────────────────────────────────────────

/// A field descriptor, written in a message's `pb_fields`.
pub const Field = schema.Field;
/// The proto type of a field (`.int32`, `.sint64`, `.string`, …).
pub const Kind = schema.Kind;
/// Sink for fields the decoder did not recognise: declare one field of this
/// type in a message struct and unknown fields survive a round trip.
pub const Unknown = schema.Unknown;
/// Derived field table — exposed for tooling/introspection, comptime-only.
pub const infos = schema.infos;

// ── wire primitives ─────────────────────────────────────────────────────────

/// Varints, zigzag, tags and the bounds-checked cursor. Useful on its own
/// for hand-rolling a frame that embeds protobuf (gRPC length prefixes,
/// custom envelopes).
pub const wire = wire_mod;

// ── encode ──────────────────────────────────────────────────────────────────

pub const EncodeOptions = encode_mod.Options;
pub const EncodeError = encode_mod.Error;
/// Wire length of `value`, without encoding it.
pub const encodedSize = encode_mod.encodedSize;
/// Encode into a caller-supplied buffer. No allocation.
pub const encodeInto = encode_mod.encodeInto;
/// Encode into an exactly-sized, caller-owned buffer.
pub const encodeAlloc = encode_mod.encodeAlloc;

// ── decode ──────────────────────────────────────────────────────────────────

pub const DecodeOptions = decode_mod.Options;
pub const DecodeError = decode_mod.Error;
pub const Decoded = decode_mod.Decoded;
/// Decode `input` as message `T`; the result owns an arena, freed by
/// `deinit()`.
pub const decode = decode_mod.decode;

test {
    // Every submodule's tests, explicitly — a `pub const` re-export does not
    // pull them in (CONVENTIONS.md §6.3, the dark-tests rule).
    _ = wire_mod;
    _ = schema;
    _ = encode_mod;
    _ = decode_mod;
    _ = @import("codec_test.zig");
    _ = @import("adversarial.zig");
    _ = @import("reference_interop.zig");
    _ = @import("golden_test.zig");
}

test "readme example round trips" {
    const Point = struct {
        x: i32 = 0,
        y: i32 = 0,
        label: []const u8 = "",
        pub const pb_fields = .{
            .x = Field{ .number = 1, .kind = .sint32 },
            .y = Field{ .number = 2, .kind = .sint32 },
            .label = Field{ .number = 3, .kind = .string },
        };
    };

    const gpa = std.testing.allocator;
    const bytes = try encodeAlloc(gpa, Point{ .x = -3, .y = 7, .label = "p" }, .{});
    defer gpa.free(bytes);

    var decoded = try decode(Point, gpa, bytes, .{});
    defer decoded.deinit();

    try std.testing.expectEqual(@as(i32, -3), decoded.value.x);
    try std.testing.expectEqual(@as(i32, 7), decoded.value.y);
    try std.testing.expectEqualStrings("p", decoded.value.label);
}
